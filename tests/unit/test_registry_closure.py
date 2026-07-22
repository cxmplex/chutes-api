import hashlib
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import AsyncMock, Mock, patch

import pytest
from fastapi import HTTPException

from api.host.schemas import RegistrySession, canonical_sha256
from api.registry import router as registry_router
from api.registry.oci import (
    OciClosureError,
    _Resolver,
    resolve_oci_descriptor_closure,
)


def _manifest(document):
    payload = json.dumps(
        document,
        sort_keys=True,
        separators=(",", ":"),
    ).encode()
    return payload, f"sha256:{hashlib.sha256(payload).hexdigest()}"


def _descriptor(media_type, digest, size):
    return {"mediaType": media_type, "digest": digest, "size": size}


class _Content:
    def __init__(self, payload):
        self.payload = payload

    async def iter_chunked(self, _size):
        yield self.payload


class _Response:
    def __init__(self, payload, media_type, digest, status=200):
        self.status = status
        self.headers = {
            "Content-Type": media_type,
            "Content-Length": str(len(payload)),
            "Docker-Content-Digest": digest,
        }
        self.content = _Content(payload)

    async def __aenter__(self):
        return self

    async def __aexit__(self, *_args):
        return None


class _Session:
    def __init__(self, responses):
        self.responses = responses
        self.urls = []

    def get(self, url, **_kwargs):
        self.urls.append(url)
        reference = url.rsplit("/", 1)[-1]
        return self.responses[reference]


class _SequenceSession:
    def __init__(self, responses):
        self.responses = list(responses)
        self.calls = []

    def get(self, url, **kwargs):
        self.calls.append((url, kwargs))
        return self.responses.pop(0)


@pytest.fixture
def oci_graph():
    manifest_type = "application/vnd.oci.image.manifest.v1+json"
    index_type = "application/vnd.oci.image.index.v1+json"
    config_digest = f"sha256:{'1' * 64}"
    layer_digest = f"sha256:{'2' * 64}"
    child_payload, child_digest = _manifest(
        {
            "schemaVersion": 2,
            "mediaType": manifest_type,
            "config": _descriptor(
                "application/vnd.oci.image.config.v1+json",
                config_digest,
                10,
            ),
            "layers": [
                _descriptor(
                    "application/vnd.oci.image.layer.v1.tar+gzip",
                    layer_digest,
                    20,
                )
            ],
        }
    )
    root_payload, root_digest = _manifest(
        {
            "schemaVersion": 2,
            "mediaType": index_type,
            "manifests": [_descriptor(manifest_type, child_digest, len(child_payload))],
        }
    )
    signature_config = f"sha256:{'3' * 64}"
    signature_layer = f"sha256:{'4' * 64}"
    signature_payload, signature_digest = _manifest(
        {
            "schemaVersion": 2,
            "mediaType": manifest_type,
            "config": _descriptor(
                "application/vnd.oci.image.config.v1+json",
                signature_config,
                11,
            ),
            "layers": [
                _descriptor(
                    "application/vnd.dev.cosign.simplesigning.v1+json",
                    signature_layer,
                    21,
                )
            ],
        }
    )
    signature_tag = f"sha256-{root_digest.removeprefix('sha256:')}.sig"
    responses = {
        root_digest: _Response(root_payload, index_type, root_digest),
        child_digest: _Response(child_payload, manifest_type, child_digest),
        signature_tag: _Response(
            signature_payload,
            manifest_type,
            signature_digest,
        ),
    }
    return {
        "session": _Session(responses),
        "root_digest": root_digest,
        "child_digest": child_digest,
        "signature_digest": signature_digest,
        "signature_tag": signature_tag,
        "blobs": {
            config_digest,
            layer_digest,
            signature_config,
            signature_layer,
        },
    }


@pytest.mark.asyncio
async def test_resolver_bounds_root_index_image_and_cosign_closure(
    oci_graph,
):
    with (
        patch.object(
            registry_router.settings,
            "depot_registry",
            "trusted.registry.example",
        ),
        patch.object(registry_router.settings, "depot_registry_token", "token"),
    ):
        closure = await resolve_oci_descriptor_closure(
            "owner/image",
            oci_graph["root_digest"],
            session=oci_graph["session"],
        )

    assert set(closure.manifests) == {
        oci_graph["root_digest"],
        oci_graph["child_digest"],
        oci_graph["signature_digest"],
    }
    assert set(closure.blobs) == oci_graph["blobs"]
    assert closure.manifest_tags == (oci_graph["signature_tag"],)
    assert len(closure.sha256) == 64


@pytest.mark.asyncio
async def test_resolver_uses_trusted_internal_registry_without_depot(
    oci_graph,
):
    with (
        patch.object(registry_router.settings, "depot_registry", ""),
        patch.object(registry_router.settings, "depot_registry_token", ""),
        patch.object(
            registry_router.settings,
            "registry_host",
            "registry:5000",
        ),
        patch.object(registry_router.settings, "registry_insecure", True),
    ):
        closure = await resolve_oci_descriptor_closure(
            "owner/image",
            oci_graph["root_digest"],
            session=oci_graph["session"],
        )

    assert oci_graph["root_digest"] in closure.manifests
    assert all(url.startswith("http://registry:5000/") for url in oci_graph["session"].urls)


@pytest.mark.asyncio
async def test_resolver_rejects_registry_digest_mismatch(oci_graph):
    root = oci_graph["root_digest"]
    oci_graph["session"].responses[root].headers["Docker-Content-Digest"] = f"sha256:{'f' * 64}"
    with (
        patch.object(
            registry_router.settings,
            "depot_registry",
            "trusted.registry.example",
        ),
        patch.object(registry_router.settings, "depot_registry_token", "token"),
        pytest.raises(OciClosureError, match="do not match"),
    ):
        await resolve_oci_descriptor_closure(
            "owner/image",
            root,
            session=oci_graph["session"],
        )


@pytest.mark.asyncio
async def test_resolver_performs_exact_depot_bearer_exchange(oci_graph):
    root = oci_graph["root_digest"]
    successful = oci_graph["session"].responses[root]
    unauthorized = _Response(b"", "text/plain", f"sha256:{'0' * 64}", status=401)
    unauthorized.headers = {
        "WWW-Authenticate": (
            'Bearer realm="https://api.depot.dev/auth/registry/token",'
            'service="trusted.registry.example",'
            'scope="repository:owner/image:pull"'
        )
    }
    token_payload = json.dumps({"token": "t" * 32}).encode()
    token_response = _Response(
        token_payload,
        "application/json",
        f"sha256:{hashlib.sha256(token_payload).hexdigest()}",
    )
    session = _SequenceSession([unauthorized, token_response, successful])
    resolver = _Resolver(
        session,
        "trusted.registry.example",
        "owner/image",
        "registry-secret",
    )

    digest, _media_type, _document = await resolver._fetch_manifest(root)

    assert digest == root
    assert session.calls[0][1]["headers"]["Authorization"].startswith("Basic ")
    assert session.calls[1][0] == "https://api.depot.dev/auth/registry/token"
    assert session.calls[1][1]["params"] == {
        "service": "trusted.registry.example",
        "scope": "repository:owner/image:pull",
    }
    assert session.calls[2][1]["headers"]["Authorization"] == f"Bearer {'t' * 32}"


def test_registry_request_authorizes_only_persisted_descriptor_closure(oci_graph):
    manifests = sorted(
        [
            oci_graph["root_digest"],
            oci_graph["child_digest"],
            oci_graph["signature_digest"],
        ]
    )
    blobs = sorted(oci_graph["blobs"])
    tags = [oci_graph["signature_tag"]]
    session = RegistrySession(
        repository="owner/image",
        actions=["pull"],
        manifest_digest=oci_graph["root_digest"],
        allowed_manifests=manifests,
        allowed_blobs=blobs,
        allowed_manifest_tags=tags,
        descriptor_closure_sha256=canonical_sha256(
            {
                "schema": "chutes.oci-descriptor-closure",
                "version": 1,
                "root_manifest": oci_graph["root_digest"],
                "manifests": manifests,
                "blobs": blobs,
                "manifest_tags": tags,
            }
        ),
    )
    allowed = [
        ("GET", "/v2/"),
        ("HEAD", "/v2/"),
        (
            "GET",
            "/v2/_token?service=registry.chutes.ai&scope=repository%3Aowner%2Fimage%3Apull",
        ),
        (
            "GET",
            f"/v2/owner/image/manifests/{oci_graph['root_digest']}",
        ),
        (
            "HEAD",
            f"/v2/owner/image/manifests/{oci_graph['child_digest']}",
        ),
        (
            "GET",
            f"/v2/owner/image/manifests/{oci_graph['signature_tag']}",
        ),
        (
            "GET",
            f"/v2/owner/image/blobs/{next(iter(oci_graph['blobs']))}",
        ),
    ]
    assert all(
        registry_router._registry_request_matches(session, method, uri) for method, uri in allowed
    )
    denied = [
        ("POST", "/v2/"),
        ("GET", "/v2/?probe=1"),
        (
            "GET",
            "/v2/_token?scope=repository%3Aother%2Fimage%3Apull",
        ),
        (
            "GET",
            "/v2/_token?scope=repository%3Aowner%2Fimage%3Apull&admin=true",
        ),
        ("GET", "/v2/owner/image/manifests/latest"),
        ("GET", f"/v2/other/image/manifests/{oci_graph['root_digest']}"),
        ("GET", f"/v2/owner/image/blobs/sha256:{'f' * 64}"),
    ]
    assert all(
        not registry_router._registry_request_matches(session, method, uri)
        for method, uri in denied
    )
    with pytest.raises(ValueError):
        registry_router.RegistrySessionRequestV1.model_validate(
            {
                "repository": "owner/image",
                "manifest_digest": oci_graph["root_digest"],
                "allowed_blobs": [f"sha256:{'f' * 64}"],
            }
        )


@pytest.mark.asyncio
async def test_certificate_presented_without_session_never_falls_back():
    legacy = AsyncMock()
    request = Mock()
    with (
        patch.object(registry_router, "_legacy_registry_auth", legacy),
        pytest.raises(HTTPException) as raised,
    ):
        await registry_router.registry_auth(
            request,
            AsyncMock(),
            registry_session=None,
            original_method="GET",
            original_uri="/v2/",
            hotkey="legacy-hotkey",
            signature="signature",
            nonce="nonce",
            authorization=None,
            sig_version="2",
            client_verify="FAILED:self-signed certificate",
            client_cert="certificate",
        )
    assert raised.value.status_code == 401
    legacy.assert_not_awaited()


@pytest.mark.asyncio
async def test_session_creation_persists_resolver_derived_closure(oci_graph):
    now = datetime.now(timezone.utc)
    server = Mock(
        server_id="server-1",
        launch_reservation_id="reservation-1",
    )
    reservation = Mock(
        consumed_at=now,
        invalidated_at=None,
        server_id=server.server_id,
        role="chute",
        container_repository="owner/image",
        container_manifest_digest=oci_graph["root_digest"],
    )
    existing_result = Mock()
    existing_result.scalar_one_or_none.return_value = None
    locked_result = Mock()
    locked_result.scalar_one.return_value = server
    db = AsyncMock()
    db.get.return_value = reservation
    db.execute.side_effect = [locked_result, existing_result]
    db.add = Mock()
    closure = Mock(
        manifests=(
            oci_graph["root_digest"],
            oci_graph["child_digest"],
            oci_graph["signature_digest"],
        ),
        blobs=tuple(sorted(oci_graph["blobs"])),
        manifest_tags=(oci_graph["signature_tag"],),
        sha256="a" * 64,
    )
    request = Mock()
    with (
        patch.object(
            registry_router,
            "extract_client_cert_hash",
            return_value=AsyncMock(return_value="c" * 64),
        ),
        patch.object(
            registry_router,
            "_current_attested_model_b_server",
            AsyncMock(return_value=server),
        ),
        patch.object(
            registry_router,
            "resolve_oci_descriptor_closure",
            AsyncMock(return_value=closure),
        ),
        patch.object(registry_router.settings, "launch_config_key", "signing-key"),
    ):
        response = await registry_router.create_registry_session(
            registry_router.RegistrySessionRequestV1(
                repository="owner/image",
                manifest_digest=oci_graph["root_digest"],
            ),
            request,
            db,
        )
    row = db.add.call_args.args[0]
    assert row.allowed_manifests == list(closure.manifests)
    assert row.allowed_blobs == list(closure.blobs)
    assert row.allowed_manifest_tags == list(closure.manifest_tags)
    assert row.descriptor_closure_sha256 == closure.sha256
    assert response.expires_at > now


@pytest.mark.asyncio
async def test_active_registry_session_is_reissued_after_lost_response(oci_graph):
    now = datetime.now(timezone.utc)
    manifests = sorted(
        [
            oci_graph["root_digest"],
            oci_graph["child_digest"],
            oci_graph["signature_digest"],
        ]
    )
    blobs = sorted(oci_graph["blobs"])
    tags = [oci_graph["signature_tag"]]
    closure_sha256 = canonical_sha256(
        {
            "schema": "chutes.oci-descriptor-closure",
            "version": 1,
            "root_manifest": oci_graph["root_digest"],
            "manifests": manifests,
            "blobs": blobs,
            "manifest_tags": tags,
        }
    )
    server = Mock(
        server_id="server-1",
        launch_reservation_id="reservation-1",
    )
    reservation = Mock(
        consumed_at=now,
        invalidated_at=None,
        server_id=server.server_id,
        role="chute",
        container_repository="owner/image",
        container_manifest_digest=oci_graph["root_digest"],
    )
    existing = RegistrySession(
        session_id="session-1",
        token_id="token-1",
        server_id=server.server_id,
        attested_cert_pubkey_hash="c" * 64,
        repository="owner/image",
        actions=["pull"],
        manifest_digest=oci_graph["root_digest"],
        allowed_manifests=manifests,
        allowed_blobs=blobs,
        allowed_manifest_tags=tags,
        descriptor_closure_sha256=closure_sha256,
        issued_at=now,
        expires_at=now + timedelta(minutes=5),
    )
    locked_result = Mock()
    locked_result.scalar_one.return_value = server
    existing_result = Mock()
    existing_result.scalar_one_or_none.return_value = existing
    db = AsyncMock()
    db.get.return_value = reservation
    db.execute.side_effect = [locked_result, existing_result]
    resolver = AsyncMock()

    with (
        patch.object(
            registry_router,
            "extract_client_cert_hash",
            return_value=AsyncMock(return_value="c" * 64),
        ),
        patch.object(
            registry_router,
            "_current_attested_model_b_server",
            AsyncMock(return_value=server),
        ),
        patch.object(
            registry_router,
            "resolve_oci_descriptor_closure",
            resolver,
        ),
        patch.object(registry_router.settings, "launch_config_key", "signing-key"),
    ):
        response = await registry_router.create_registry_session(
            registry_router.RegistrySessionRequestV1(
                repository="owner/image",
                manifest_digest=oci_graph["root_digest"],
            ),
            Mock(),
            db,
        )

    assert isinstance(response.token, str)
    assert response.expires_at == existing.expires_at
    resolver.assert_not_awaited()
    db.commit.assert_not_awaited()


def test_registry_nginx_authenticates_probe_token_manifest_and_blob_paths():
    chart = (
        Path(__file__).resolve().parents[2] / "charts/templates/registry-proxy-cm.yaml"
    ).read_text()
    assert "location /v2/_token" in chart
    assert "location /v2/" in chart
    assert chart.count("auth_request /auth;") == 2
    assert "limit_except GET HEAD" in chart
    assert "X-Chutes-Registry-Session $http_x_chutes_registry_session" in chart
    assert "X-Chutes-Registry-Method $request_method" in chart
    assert "X-Chutes-Registry-Uri $request_uri" in chart
    assert "X-Client-Cert $ssl_client_escaped_cert" in chart
    assert "X-Client-Verify $ssl_client_verify" in chart
