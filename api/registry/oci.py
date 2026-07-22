"""Bounded OCI descriptor-closure resolution against the trusted Depot registry."""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from typing import Any, Dict, Optional
from urllib.parse import urlsplit
from urllib.request import parse_http_list, parse_keqv_list

import aiohttp

from api.config import settings
from api.host.schemas import canonical_sha256

OCI_INDEX_TYPES = {
    "application/vnd.oci.image.index.v1+json",
    "application/vnd.docker.distribution.manifest.list.v2+json",
}
OCI_MANIFEST_TYPES = {
    "application/vnd.oci.image.manifest.v1+json",
    "application/vnd.docker.distribution.manifest.v2+json",
}
OCI_ACCEPT = ", ".join(sorted(OCI_INDEX_TYPES | OCI_MANIFEST_TYPES))
MAX_MANIFEST_BYTES = 4 * 1024 * 1024
MAX_TOKEN_RESPONSE_BYTES = 64 * 1024
MAX_MANIFESTS = 128
MAX_BLOBS = 2048
MAX_DEPTH = 8
MAX_DESCRIPTOR_SIZE = 16 * 1024**4
_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
_COSIGN_TAG = re.compile(r"^sha256-[0-9a-f]{64}\.sig$")


class OciClosureError(ValueError):
    pass


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> Dict[str, Any]:
    result: Dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise OciClosureError(f"duplicate OCI manifest key: {key}")
        result[key] = value
    return result


def _manifest_document(payload: bytes) -> Dict[str, Any]:
    try:
        document = json.loads(
            payload.decode("utf-8"),
            object_pairs_hook=_reject_duplicate_keys,
            parse_constant=lambda value: (_ for _ in ()).throw(
                OciClosureError(f"invalid OCI JSON constant: {value}")
            ),
        )
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
        if isinstance(exc, OciClosureError):
            raise
        raise OciClosureError("registry returned invalid OCI manifest JSON") from exc
    if not isinstance(document, dict) or document.get("schemaVersion") != 2:
        raise OciClosureError("OCI manifest must be one schema-version 2 object")
    return document


def _descriptor(value: Any) -> tuple[str, int, str]:
    if not isinstance(value, dict):
        raise OciClosureError("OCI descriptor must be an object")
    digest = value.get("digest")
    size = value.get("size")
    media_type = value.get("mediaType")
    if (
        not isinstance(digest, str)
        or not _DIGEST.fullmatch(digest)
        or not isinstance(size, int)
        or isinstance(size, bool)
        or not 0 <= size <= MAX_DESCRIPTOR_SIZE
        or not isinstance(media_type, str)
        or not media_type
        or len(media_type) > 255
    ):
        raise OciClosureError("OCI descriptor digest, size, or media type is invalid")
    return digest, size, media_type


@dataclass(frozen=True)
class OciDescriptorClosure:
    manifests: tuple[str, ...]
    blobs: tuple[str, ...]
    manifest_tags: tuple[str, ...]
    sha256: str


class _Resolver:
    def __init__(
        self,
        session: aiohttp.ClientSession,
        registry: str,
        repository: str,
        registry_token: Optional[str],
        *,
        scheme: str = "https",
    ):
        self.session = session
        self.registry = registry
        self.repository = repository
        self.scheme = scheme
        self.basic_authorization = (
            aiohttp.BasicAuth(
                "x-token",
                registry_token,
            ).encode()
            if registry_token
            else None
        )
        self.bearer_token: Optional[str] = None
        self.manifests: set[str] = set()
        self.blobs: set[str] = set()
        self.manifest_tags: set[str] = set()

    async def _bounded_payload(
        self,
        response: aiohttp.ClientResponse,
        limit: int,
    ) -> bytes:
        chunks = []
        total = 0
        async for chunk in response.content.iter_chunked(64 * 1024):
            total += len(chunk)
            if total > limit:
                raise OciClosureError("trusted registry response exceeds its size bound")
            chunks.append(chunk)
        return b"".join(chunks)

    async def _exchange_bearer_token(self, challenge: str) -> None:
        if self.basic_authorization is None:
            raise OciClosureError(
                "trusted local registry unexpectedly required bearer authentication"
            )
        try:
            scheme, parameters = challenge.split(" ", 1)
            values = parse_keqv_list(parse_http_list(parameters))
            realm = values["realm"]
            service = values["service"]
            scope = values["scope"]
        except (KeyError, ValueError) as exc:
            raise OciClosureError(
                "trusted registry returned an invalid authentication challenge"
            ) from exc
        parsed = urlsplit(realm)
        expected_scope = f"repository:{self.repository}:pull"
        if (
            scheme.lower() != "bearer"
            or parsed.scheme != "https"
            or parsed.hostname != "api.depot.dev"
            or parsed.port not in (None, 443)
            or parsed.username is not None
            or parsed.password is not None
            or parsed.path != "/auth/registry/token"
            or parsed.query
            or parsed.fragment
            or service != self.registry
            or scope != expected_scope
        ):
            raise OciClosureError(
                "trusted registry authentication challenge changed identity or scope"
            )
        async with self.session.get(
            realm,
            params={"service": service, "scope": scope},
            headers={"Authorization": self.basic_authorization},
            allow_redirects=False,
        ) as response:
            if response.status != 200:
                raise OciClosureError(
                    f"trusted registry token exchange failed with HTTP {response.status}"
                )
            payload = await self._bounded_payload(
                response,
                MAX_TOKEN_RESPONSE_BYTES,
            )
        try:
            document = json.loads(
                payload.decode("utf-8"),
                object_pairs_hook=_reject_duplicate_keys,
            )
        except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
            raise OciClosureError("trusted registry token response is invalid") from exc
        token = document.get("token") if isinstance(document, dict) else None
        access_token = document.get("access_token") if isinstance(document, dict) else None
        if token is None:
            token = access_token
        if (
            not isinstance(token, str)
            or not 16 <= len(token) <= 16384
            or (access_token is not None and access_token != token)
            or any(ord(character) < 0x21 or ord(character) > 0x7E for character in token)
        ):
            raise OciClosureError("trusted registry bearer token is invalid")
        self.bearer_token = token

    async def _manifest_response(
        self,
        url: str,
    ) -> tuple[Dict[str, str], bytes]:
        for attempt in range(2):
            authorization = (
                f"Bearer {self.bearer_token}" if self.bearer_token else self.basic_authorization
            )
            headers = {"Accept": OCI_ACCEPT}
            if authorization:
                headers["Authorization"] = authorization
            async with self.session.get(
                url,
                headers=headers,
                allow_redirects=False,
            ) as response:
                if response.status == 401 and attempt == 0:
                    challenge = response.headers.get("WWW-Authenticate", "")
                elif response.status != 200:
                    raise OciClosureError(
                        f"trusted registry manifest lookup failed with HTTP {response.status}"
                    )
                else:
                    content_length = response.headers.get("Content-Length")
                    if content_length is not None:
                        try:
                            declared_length = int(content_length)
                        except ValueError as exc:
                            raise OciClosureError("OCI manifest Content-Length is invalid") from exc
                        if declared_length > MAX_MANIFEST_BYTES:
                            raise OciClosureError("OCI manifest exceeds the bounded size")
                    payload = await self._bounded_payload(
                        response,
                        MAX_MANIFEST_BYTES,
                    )
                    return dict(response.headers), payload
            await self._exchange_bearer_token(challenge)
        raise OciClosureError("trusted registry authentication did not converge")

    async def _fetch_manifest(
        self,
        reference: str,
        *,
        expected_size: Optional[int] = None,
    ) -> tuple[str, str, Dict[str, Any]]:
        if not (_DIGEST.fullmatch(reference) or _COSIGN_TAG.fullmatch(reference)):
            raise OciClosureError("OCI manifest reference is not canonical")
        url = f"{self.scheme}://{self.registry}/v2/{self.repository}/manifests/{reference}"
        headers, payload = await self._manifest_response(url)
        if not payload:
            raise OciClosureError("OCI manifest has an invalid bounded size")
        media_type = headers.get("Content-Type", "").split(";", 1)[0].strip()
        registry_digest = headers.get(
            "Docker-Content-Digest",
            "",
        ).lower()
        calculated = f"sha256:{hashlib.sha256(payload).hexdigest()}"
        if (
            not _DIGEST.fullmatch(registry_digest)
            or registry_digest != calculated
            or (_DIGEST.fullmatch(reference) and reference != calculated)
            or (expected_size is not None and len(payload) != expected_size)
        ):
            raise OciClosureError("trusted registry manifest bytes do not match their descriptor")
        document = _manifest_document(payload)
        declared_media_type = document.get("mediaType")
        if declared_media_type is not None and declared_media_type != media_type:
            raise OciClosureError("OCI manifest media type disagrees with the registry response")
        if media_type not in OCI_INDEX_TYPES | OCI_MANIFEST_TYPES:
            raise OciClosureError("OCI manifest media type is unsupported")
        return calculated, media_type, document

    def _add_manifest(self, digest: str) -> None:
        self.manifests.add(digest)
        if len(self.manifests) > MAX_MANIFESTS:
            raise OciClosureError("OCI closure contains too many manifests")

    def _add_blob(self, digest: str) -> None:
        self.blobs.add(digest)
        if len(self.blobs) > MAX_BLOBS:
            raise OciClosureError("OCI closure contains too many blobs")

    async def walk(
        self,
        reference: str,
        *,
        expected_size: Optional[int] = None,
        depth: int = 0,
    ) -> str:
        if depth > MAX_DEPTH:
            raise OciClosureError("OCI descriptor graph exceeds the depth bound")
        digest, media_type, document = await self._fetch_manifest(
            reference,
            expected_size=expected_size,
        )
        if digest in self.manifests:
            return digest
        self._add_manifest(digest)
        if media_type in OCI_INDEX_TYPES:
            manifests = document.get("manifests")
            if not isinstance(manifests, list) or not manifests:
                raise OciClosureError("OCI image index has no manifests")
            for child in manifests:
                child_digest, child_size, child_media_type = _descriptor(child)
                if child_media_type not in OCI_INDEX_TYPES | OCI_MANIFEST_TYPES:
                    raise OciClosureError("OCI image index references an unsupported manifest type")
                await self.walk(
                    child_digest,
                    expected_size=child_size,
                    depth=depth + 1,
                )
            return digest

        config_digest, _config_size, _config_media_type = _descriptor(document.get("config"))
        self._add_blob(config_digest)
        layers = document.get("layers")
        if not isinstance(layers, list):
            raise OciClosureError("OCI image manifest layers must be an array")
        for layer in layers:
            layer_digest, _layer_size, _layer_media_type = _descriptor(layer)
            self._add_blob(layer_digest)
        return digest

    async def resolve(self, root_digest: str) -> OciDescriptorClosure:
        await self.walk(root_digest)
        signature_tag = f"sha256-{root_digest.removeprefix('sha256:')}.sig"
        signature_digest = await self.walk(signature_tag)
        if signature_digest == root_digest:
            raise OciClosureError("cosign signature manifest aliases the root manifest")
        self.manifest_tags.add(signature_tag)
        document = {
            "schema": "chutes.oci-descriptor-closure",
            "version": 1,
            "root_manifest": root_digest,
            "manifests": sorted(self.manifests),
            "blobs": sorted(self.blobs),
            "manifest_tags": sorted(self.manifest_tags),
        }
        return OciDescriptorClosure(
            manifests=tuple(document["manifests"]),
            blobs=tuple(document["blobs"]),
            manifest_tags=tuple(document["manifest_tags"]),
            sha256=canonical_sha256(document),
        )


async def resolve_oci_descriptor_closure(
    repository: str,
    root_digest: str,
    *,
    session: Optional[aiohttp.ClientSession] = None,
) -> OciDescriptorClosure:
    """Resolve root/index/image/cosign descriptors using registry read credentials."""

    depot_registry = settings.depot_registry.strip().rstrip("/")
    depot_token = settings.depot_registry_token
    if bool(depot_registry) != bool(depot_token):
        raise OciClosureError("trusted Depot registry and read token must be configured together")
    if depot_registry:
        registry = depot_registry
        token: Optional[str] = depot_token
        scheme = "https"
    else:
        registry = settings.registry_host.strip().rstrip("/")
        token = None
        scheme = "http" if settings.registry_insecure else "https"
    try:
        parsed_registry = urlsplit(f"{scheme}://{registry}")
        registry_port = parsed_registry.port
    except ValueError as exc:
        raise OciClosureError("trusted registry authority is invalid") from exc
    if (
        not registry
        or "/" in registry
        or "://" in registry
        or parsed_registry.hostname is None
        or parsed_registry.username is not None
        or parsed_registry.password is not None
        or registry_port is not None
        and not 1 <= registry_port <= 65535
        or not _DIGEST.fullmatch(root_digest)
    ):
        raise OciClosureError("trusted internal registry resolver is not configured canonically")
    if session is not None:
        return await _Resolver(
            session,
            registry,
            repository,
            token,
            scheme=scheme,
        ).resolve(root_digest)
    timeout = aiohttp.ClientTimeout(total=60, connect=15, sock_read=30)
    async with aiohttp.ClientSession(
        timeout=timeout,
        auto_decompress=False,
    ) as owned_session:
        return await _Resolver(
            owned_session,
            registry,
            repository,
            token,
            scheme=scheme,
        ).resolve(root_digest)
