"""
Router for misc. stuff, e.g. score proxy.
"""

import asyncio
import aiohttp
import hashlib
import orjson as json
import re
from loguru import logger
from typing import Optional
from huggingface_hub import HfApi
from huggingface_hub.utils import (
    RepositoryNotFoundError,
    RevisionNotFoundError,
    GatedRepoError,
    HfHubHTTPError,
)
from urllib.parse import urlparse
from fastapi import APIRouter, Header, Request, Response, HTTPException, status, Query
from fastapi.responses import StreamingResponse
from typing import AsyncIterator
from sqlalchemy import select
from ipaddress import ip_address
from api.config import settings
from api.database import get_session
from api.chute.util import get_one
from api.chute.schemas import Chute, LLMDetail
from api.util import extract_hf_model_name, get_resolved_ips, is_invalid_ip

router = APIRouter()


ALLOWED_DOMAINS = [
    "scoredata.me",
    "s3.hippius.com",
]


async def _get_llm_root_map() -> dict[str, str]:
    """
    Build a cached mapping of HF repo root -> chute name from llm_details.
    """
    cache_key = "hf_root_to_chute_name"
    cached = await settings.redis_client.get(cache_key)
    if cached:
        try:
            return json.loads(cached)
        except Exception:
            await settings.redis_client.delete(cache_key)

    root_map = {}
    async with get_session(readonly=True) as session:
        rows = await session.execute(
            select(LLMDetail.details).where(LLMDetail.details.is_not(None))
        )
        for (details,) in rows:
            root = details.get("root") if isinstance(details, dict) else None
            name = details.get("id") if isinstance(details, dict) else None
            if root and name:
                root_map[root] = name

    await settings.redis_client.set(cache_key, json.dumps(root_map).decode(), ex=300)
    return root_map


async def _get_template_model_map() -> dict[str, str]:
    """Map literal standard-template HuggingFace repos to chute IDs, including diffusion/embedding."""
    cache_key = "hf_repo_to_standard_template_chute"
    cached = await settings.redis_client.get(cache_key)
    if cached:
        try:
            return json.loads(cached)
        except Exception:
            await settings.redis_client.delete(cache_key)

    model_map = {}
    async with get_session() as session:
        rows = (
            await session.execute(
                select(Chute.chute_id, Chute.code)
                .where(Chute.standard_template.in_(("vllm", "embedding", "diffusion")))
                .order_by(Chute.chute_id)
            )
        ).all()
        for chute_id, code in rows:
            repo_id = extract_hf_model_name(chute_id, code)
            if repo_id and not repo_id.lower().startswith(("http://", "https://")):
                model_map.setdefault(repo_id, chute_id)

    await settings.redis_client.set(cache_key, json.dumps(model_map).decode(), ex=300)
    return model_map


async def is_url_allowed(url: str) -> bool:
    parsed = urlparse(url)
    hostname = parsed.hostname
    if not hostname:
        return False
    if not any(hostname == domain or hostname.endswith("." + domain) for domain in ALLOWED_DOMAINS):
        return False

    # Resolve and reject private/loopback IPs to prevent SSRF to internal services.
    try:
        # Check if hostname is already an IP literal.
        try:
            ip = ip_address(hostname)
            if is_invalid_ip(ip):
                return False
            return True
        except ValueError:
            pass

        resolved = await get_resolved_ips(hostname)
        if any(is_invalid_ip(ip) for ip in resolved):
            return False
    except ValueError:
        return False

    return True


@router.get("/proxy")
async def proxy(
    url: str,
    request: Request,
    stream: bool = Query(False, description="Stream the response for large files/videos"),
):
    if url == "ping":
        return {"pong": True}

    if not url.startswith(("http://", "https://")) or not await is_url_allowed(url):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Invalid or unauthorized URL.",
        )

    # Configure headers to forward.
    headers_to_forward = {}
    skip_headers = {
        "host",
        "connection",
        "content-length",
        "content-encoding",
        "transfer-encoding",
        "upgrade",
    }
    for header_name, header_value in request.headers.items():
        if header_name.lower() not in skip_headers:
            headers_to_forward[header_name] = header_value
    timeout = aiohttp.ClientTimeout(connect=10.0, total=300.0)

    # Headers to forward from the upstream response
    forward_response_headers = [
        "content-type",
        "content-length",
        "accept-ranges",
        "content-range",
        "cache-control",
        "etag",
        "last-modified",
        "expires",
        "date",
    ]

    try:
        if stream:
            session = aiohttp.ClientSession(timeout=timeout)
            response = await session.get(url, headers=headers_to_forward)
            if not response.ok:
                await response.close()
                await session.close()
                raise HTTPException(
                    status_code=response.status,
                    detail=f"Upstream server returned {response.status}",
                )
            response_headers = {}
            for header in forward_response_headers:
                if header in response.headers:
                    response_headers[header] = response.headers[header]

            async def stream_content() -> AsyncIterator[bytes]:
                try:
                    async for chunk in response.content.iter_chunked(8192):
                        yield chunk
                finally:
                    await response.close()
                    await session.close()

            return StreamingResponse(
                stream_content(),
                status_code=response.status,
                headers=response_headers,
                media_type=response_headers.get("content-type", "application/octet-stream"),
            )

        else:
            async with aiohttp.ClientSession(timeout=timeout) as session:
                async with session.get(url, headers=headers_to_forward) as response:
                    content = await response.read()

                    response_headers = {}
                    for header in forward_response_headers:
                        if header in response.headers:
                            response_headers[header] = response.headers[header]

                    return Response(
                        content=content,
                        status_code=response.status,
                        headers=response_headers,
                    )

    except HTTPException:
        raise
    except aiohttp.ClientTimeout:
        logger.error(f"WHITELIST_PROXY: upstream gateway timeout: {url=} {stream=}")
        raise HTTPException(
            status_code=status.HTTP_504_GATEWAY_TIMEOUT,
            detail="Upstream server timeout",
        )
    except aiohttp.ClientError as e:
        logger.error(
            f"WHITELIST_PROXY: upstream gateway request failed: {url=} {stream=} exception={str(e)}"
        )
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail=f"Upstream server returned error: {str(e)}",
        )
    except Exception as e:
        logger.error(
            f"WHITELIST_PROXY: unhandled exception proxying upstream request: {url=} {stream=} exception={str(e)}"
        )
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Unhandled exception proxying request: {str(e)}",
        )


@router.put("/proxy")
async def proxy_put(
    url: str,
    request: Request,
):
    if not url.startswith(("http://", "https://")) or not await is_url_allowed(url):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Invalid or unauthorized URL.",
        )

    headers_to_forward = {}
    skip_headers = {
        "host",
        "connection",
        "transfer-encoding",
        "upgrade",
    }
    for header_name, header_value in request.headers.items():
        if header_name.lower() not in skip_headers:
            headers_to_forward[header_name] = header_value

    body = await request.body()
    timeout = aiohttp.ClientTimeout(connect=10.0, total=3600.0)

    try:
        async with aiohttp.ClientSession(timeout=timeout) as session:
            async with session.put(url, headers=headers_to_forward, data=body) as response:
                content = await response.read()

                response_headers = {}
                forward_response_headers = [
                    "content-type",
                    "content-length",
                    "etag",
                    "x-amz-request-id",
                    "x-amz-id-2",
                    "x-amz-version-id",
                    "location",
                    "cache-control",
                    "last-modified",
                    "expires",
                    "date",
                ]
                for header in forward_response_headers:
                    if header in response.headers:
                        response_headers[header] = response.headers[header]

                return Response(
                    content=content,
                    status_code=response.status,
                    headers=response_headers,
                )

    except HTTPException:
        raise
    except aiohttp.ClientTimeout:
        logger.error(f"WHITELIST_PROXY: upstream gateway timeout on PUT: {url=}")
        raise HTTPException(
            status_code=status.HTTP_504_GATEWAY_TIMEOUT,
            detail="Upstream server timeout",
        )
    except aiohttp.ClientError as e:
        logger.error(
            f"WHITELIST_PROXY: upstream gateway PUT request failed: {url=} exception={str(e)}"
        )
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail=f"Upstream server returned error: {str(e)}",
        )
    except Exception as e:
        logger.error(
            f"WHITELIST_PROXY: unhandled exception proxying PUT request: {url=} exception={str(e)}"
        )
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Unhandled exception proxying request: {str(e)}",
        )


_IMMUTABLE_HF_REVISION = re.compile(r"^[0-9a-f]{40}$")
HF_REF_CACHE_TTL_SECONDS = 300


def _resolve_repo_revision_sync(
    repo_id: str, repo_type: str, revision: str, hf_token: Optional[str]
) -> str:
    """Resolve a branch/tag/commit through HuggingFace to one immutable commit."""
    api = HfApi(token=hf_token)
    commit_hash = api.repo_info(repo_id=repo_id, revision=revision, repo_type=repo_type).sha
    commit_hash = str(commit_hash or "").strip().lower()
    if not _IMMUTABLE_HF_REVISION.fullmatch(commit_hash):
        raise ValueError("HuggingFace returned a non-immutable commit identifier")
    return commit_hash


def _fetch_repo_manifest_sync(
    repo_id: str, repo_type: str, commit_hash: str, hf_token: Optional[str]
):
    """Load an immutable HuggingFace commit manifest for cache validation."""
    api = HfApi(token=hf_token)
    repo_items = api.list_repo_tree(
        repo_id=repo_id,
        revision=commit_hash,
        repo_type=repo_type,
        recursive=True,
    )
    files = []
    directories = []
    for item in repo_items:
        # Directories don't have size, but have tree_id
        if not hasattr(item, "size"):
            directories.append(item.path)
            continue
        file_info = {
            "path": item.path,
            "size": getattr(item, "size", None),
        }
        if hasattr(item, "lfs") and item.lfs:
            file_info["sha256"] = item.lfs.sha256
            file_info["is_lfs"] = True
        else:
            file_info["blob_id"] = getattr(item, "blob_id", None)
            file_info["is_lfs"] = False
        files.append(file_info)

    return {
        "repo_id": repo_id,
        "repo_type": repo_type,
        "revision": commit_hash,
        "commit_hash": commit_hash,
        "files": files,
        "directories": directories,
    }


def _hf_cache_key(kind: str, *parts: str) -> str:
    encoded = json.dumps(parts)
    return f"hf_repo_info:{kind}:{hashlib.sha256(encoded).hexdigest()}"


@router.get("/hf_repo_info")
async def get_hf_repo_info(
    repo_id: str = Query(...),
    repo_type: str = Query("model"),
    revision: str = Query("main"),
    x_hf_token: Optional[str] = Header(None),
):
    """
    Proxy endpoint for HF repo file info.
    """
    # Credentials are accepted only in an authenticated header so request targets and access logs
    # cannot contain a gated-model token.
    hf_token = x_hf_token

    # Chute exists?
    chute = await get_one(repo_id)
    if not chute:
        chute = await get_one(f"{repo_id}-TEE")
    if not chute and repo_id == "Qwen/Qwen-Image-2512":
        chute = await get_one("Qwen-Image-2512")
    if not chute:
        # The repo_id might be an actual HF repo that differs from our chute name.
        # Look it up in the llm_details root mapping.
        root_map = await _get_llm_root_map()
        chute_name = root_map.get(repo_id)
        if chute_name:
            chute = await get_one(chute_name)
    if not chute:
        template_model_map = await _get_template_model_map()
        chute_id = template_model_map.get(repo_id)
        if chute_id:
            chute = await get_one(chute_id)
    if not chute:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"No chute found for model {repo_id}",
        )

    token_scope = hashlib.sha256(hf_token.encode()).hexdigest() if hf_token else ""
    requested_revision = revision.strip()
    immutable_request = _IMMUTABLE_HF_REVISION.fullmatch(requested_revision.lower())

    try:
        if immutable_request:
            commit_hash = requested_revision.lower()
        else:
            ref_cache_key = _hf_cache_key(
                "ref", repo_id, repo_type, requested_revision, token_scope
            )
            cached_commit = await settings.redis_client.get(ref_cache_key)
            commit_hash = (
                cached_commit.decode() if isinstance(cached_commit, bytes) else cached_commit
            )
            if not commit_hash or not _IMMUTABLE_HF_REVISION.fullmatch(commit_hash):
                commit_hash = await asyncio.to_thread(
                    _resolve_repo_revision_sync,
                    repo_id,
                    repo_type,
                    requested_revision,
                    hf_token,
                )
                await settings.redis_client.set(
                    ref_cache_key,
                    commit_hash,
                    ex=HF_REF_CACHE_TTL_SECONDS,
                )

        # Immutable manifests have no TTL. Mutable names cache only their short-lived
        # ref->commit mapping above; after it expires the branch/tag is resolved again.
        manifest_cache_key = _hf_cache_key("commit", repo_id, repo_type, commit_hash, token_scope)
        cached_manifest = await settings.redis_client.get(manifest_cache_key)
        if cached_manifest:
            try:
                result = json.loads(cached_manifest)
            except Exception:
                await settings.redis_client.delete(manifest_cache_key)
                result = None
        else:
            result = None
        if result is None:
            result = await asyncio.to_thread(
                _fetch_repo_manifest_sync,
                repo_id,
                repo_type,
                commit_hash,
                hf_token,
            )
            await settings.redis_client.set(manifest_cache_key, json.dumps(result).decode())
    except RepositoryNotFoundError:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Repository '{repo_id}' not found on HuggingFace",
        )
    except RevisionNotFoundError:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Revision '{revision}' not found in repository '{repo_id}'",
        )
    except GatedRepoError:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Repository '{repo_id}' is gated; valid HF token required",
        )
    except HfHubHTTPError as e:
        if e.response is not None and e.response.status_code in (401, 403):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Access denied to '{repo_id}': invalid or missing credentials",
            )
        raise HTTPException(status_code=status.HTTP_502_BAD_GATEWAY, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(e))

    return {**result, "requested_revision": requested_revision}
