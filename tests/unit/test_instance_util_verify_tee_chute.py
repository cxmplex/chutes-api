"""
Unit tests for verify_tee_chute in api/instance/util.py.
Tests chute attestation flow with e2e_pubkey hash for chutes >= 0.6.0.
"""

import hashlib
import pytest
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch
from fastapi import HTTPException

from api.config import (
    TeeMeasurementConfig,
    measurement_config_fingerprint,
    measurement_trust_set_fingerprint,
    settings,
)
from api.instance.util import verify_tee_chute, require_attested_client_cert
from api.server.exceptions import NoClientCertError
from api.server.quote import BootTdxQuote
from tests.fixtures.gpus import TEST_GPU_NONCE

EXPECTED_NONCE = TEST_GPU_NONCE
E2E_PUBKEY = "dGVzdF9lMmVfcHVia2V5"  # base64-like test value
EXPECTED_CERT_HASH = "a" * 64


def _make_instance(chutes_version: str | None, extra: dict | None = None):
    """Create a mock Instance with host, chutes_version, extra."""
    instance = MagicMock()
    instance.host = "192.168.1.1"
    instance.chutes_version = chutes_version
    instance.extra = extra
    # Explicit None: a MagicMock auto-attribute is truthy, which would take the
    # server_id resolution branch instead of the legacy host+hotkey fallback.
    instance.server_id = None
    return instance


def _make_launch_config():
    """Create a mock LaunchConfig."""
    launch_config = MagicMock()
    launch_config.miner_hotkey = "miner_hotkey_123"
    return launch_config


def _make_server():
    """Create a mock Server."""
    server = MagicMock()
    server.ip = "192.168.1.1"
    server.miner_hotkey = "miner_hotkey_123"
    # Explicit False: a truthy auto-attribute would short-circuit verify_tee_chute
    # down the self-registered (no proxy dial) path, skipping the assertions under test.
    server.self_registered = False
    return server


@pytest.fixture
def mock_db():
    """Mock database session that returns a server for the query."""
    db = AsyncMock()
    result = MagicMock()
    result.scalar_one_or_none.return_value = _make_server()
    db.execute = AsyncMock(return_value=result)
    return db


@pytest.fixture
def sample_quote():
    """Sample BootTdxQuote for testing."""
    return BootTdxQuote(
        version=4,
        att_key_type=2,
        tee_type=0x81,
        mrtd="a" * 96,
        rtmr0="b" * 96,
        rtmr1="c" * 96,
        rtmr2="d" * 96,
        rtmr3="e" * 96,
        report_data=EXPECTED_NONCE + "0" * 64,
        user_data="test",
        platform_id="0" * 32,
        raw_quote_size=4096,
        parsed_at="2024-01-01T00:00:00Z",
        raw_bytes=b"dummy",
    )


@pytest.fixture
def mock_cert():
    """Mock x509 certificate with get_public_key_hash returning expected hash."""
    cert = MagicMock()
    return cert


@pytest.mark.asyncio
async def test_verify_tee_chute_chutes_060_uses_e2e_pubkey_hash(mock_db, sample_quote, mock_cert):
    """For chutes >= 0.6.0 with e2e_pubkey, verify_quote receives sha256(nonce+e2e_pubkey)."""
    instance = _make_instance("0.6.0", {"e2e_pubkey": E2E_PUBKEY})
    launch_config = _make_launch_config()

    expected_report_data = (
        hashlib.sha256((EXPECTED_NONCE + E2E_PUBKEY).encode()).hexdigest().lower()
    )

    with (
        patch("api.instance.util.TeeServerClient") as mock_client_cls,
        patch("api.instance.util.verify_quote", new_callable=AsyncMock) as mock_verify_quote,
        patch("api.instance.util.verify_gpu_evidence", new_callable=AsyncMock) as mock_verify_gpu,
        patch("api.instance.util.get_public_key_hash", return_value=EXPECTED_CERT_HASH),
    ):
        mock_client = MagicMock()
        mock_client.get_chute_evidence = AsyncMock(return_value=(sample_quote, [], mock_cert))
        mock_client_cls.return_value = mock_client

        await verify_tee_chute(mock_db, instance, launch_config, "deploy-123", EXPECTED_NONCE)

        mock_verify_quote.assert_called_once_with(
            sample_quote, expected_report_data, EXPECTED_CERT_HASH
        )
        mock_verify_gpu.assert_called_once_with([], expected_report_data)


@pytest.mark.asyncio
async def test_verify_tee_chute_cpu_skips_gpu_evidence(mock_db, sample_quote, mock_cert):
    """For CPU chutes (compute_type='cpu'), verify_quote runs but verify_gpu_evidence is skipped."""
    instance = _make_instance("0.6.0", {"e2e_pubkey": E2E_PUBKEY})
    launch_config = _make_launch_config()

    expected_report_data = (
        hashlib.sha256((EXPECTED_NONCE + E2E_PUBKEY).encode()).hexdigest().lower()
    )

    with (
        patch("api.instance.util.TeeServerClient") as mock_client_cls,
        patch("api.instance.util.verify_quote", new_callable=AsyncMock) as mock_verify_quote,
        patch("api.instance.util.verify_gpu_evidence", new_callable=AsyncMock) as mock_verify_gpu,
        patch("api.instance.util.get_public_key_hash", return_value=EXPECTED_CERT_HASH),
    ):
        mock_client = MagicMock()
        # CPU chute proxies return null nvtrust_evidence -> get_chute_evidence yields None.
        mock_client.get_chute_evidence = AsyncMock(return_value=(sample_quote, None, mock_cert))
        mock_client_cls.return_value = mock_client

        await verify_tee_chute(
            mock_db,
            instance,
            launch_config,
            "deploy-123",
            EXPECTED_NONCE,
            compute_type="cpu",
        )

        mock_verify_quote.assert_called_once_with(
            sample_quote, expected_report_data, EXPECTED_CERT_HASH
        )
        mock_verify_gpu.assert_not_called()


@pytest.mark.asyncio
async def test_verify_tee_chute_chutes_059_uses_raw_nonce(mock_db, sample_quote, mock_cert):
    """For chutes < 0.6.0, verify_quote receives expected_nonce directly (old behavior)."""
    instance = _make_instance("0.5.9", {"e2e_pubkey": E2E_PUBKEY})
    launch_config = _make_launch_config()

    with (
        patch("api.instance.util.TeeServerClient") as mock_client_cls,
        patch("api.instance.util.verify_quote", new_callable=AsyncMock) as mock_verify_quote,
        patch("api.instance.util.verify_gpu_evidence", new_callable=AsyncMock) as mock_verify_gpu,
        patch("api.instance.util.get_public_key_hash", return_value=EXPECTED_CERT_HASH),
    ):
        mock_client = MagicMock()
        mock_client.get_chute_evidence = AsyncMock(return_value=(sample_quote, [], mock_cert))
        mock_client_cls.return_value = mock_client

        await verify_tee_chute(mock_db, instance, launch_config, "deploy-123", EXPECTED_NONCE)

        mock_verify_quote.assert_called_once_with(sample_quote, EXPECTED_NONCE, EXPECTED_CERT_HASH)
        mock_verify_gpu.assert_called_once_with([], EXPECTED_NONCE)


@pytest.mark.asyncio
async def test_verify_tee_chute_chutes_060_missing_e2e_pubkey_raises_400(
    mock_db, sample_quote, mock_cert
):
    """For chutes >= 0.6.0 without e2e_pubkey, raise HTTP 400."""
    instance = _make_instance("0.6.0", {})  # no e2e_pubkey
    launch_config = _make_launch_config()

    with (
        patch("api.instance.util.TeeServerClient") as mock_client_cls,
        patch("api.instance.util.verify_quote", new_callable=AsyncMock),
        patch("api.instance.util.verify_gpu_evidence", new_callable=AsyncMock),
        patch("api.instance.util.get_public_key_hash", return_value=EXPECTED_CERT_HASH),
    ):
        mock_client = MagicMock()
        mock_client.get_chute_evidence = AsyncMock(return_value=(sample_quote, [], mock_cert))
        mock_client_cls.return_value = mock_client

        with pytest.raises(HTTPException) as exc_info:
            await verify_tee_chute(mock_db, instance, launch_config, "deploy-123", EXPECTED_NONCE)

        assert exc_info.value.status_code == 400
        assert "e2e_pubkey required" in exc_info.value.detail


@pytest.mark.asyncio
async def test_verify_tee_chute_chutes_060_extra_none_raises_400(mock_db, sample_quote, mock_cert):
    """For chutes >= 0.6.0 with instance.extra None, raise HTTP 400."""
    instance = _make_instance("0.6.0", None)
    launch_config = _make_launch_config()

    with (
        patch("api.instance.util.TeeServerClient") as mock_client_cls,
        patch("api.instance.util.verify_quote", new_callable=AsyncMock),
        patch("api.instance.util.verify_gpu_evidence", new_callable=AsyncMock),
        patch("api.instance.util.get_public_key_hash", return_value=EXPECTED_CERT_HASH),
    ):
        mock_client = MagicMock()
        mock_client.get_chute_evidence = AsyncMock(return_value=(sample_quote, [], mock_cert))
        mock_client_cls.return_value = mock_client

        with pytest.raises(HTTPException) as exc_info:
            await verify_tee_chute(mock_db, instance, launch_config, "deploy-123", EXPECTED_NONCE)

        assert exc_info.value.status_code == 400


# --------------------------------------------------------------------------------------------------
# require_attested_client_cert (C-1: bind /tee secret delivery to the attested TD)
# --------------------------------------------------------------------------------------------------

_ATTESTED_PEM = "-----BEGIN CERTIFICATE-----\nMIIBdummy\n-----END CERTIFICATE-----\n"


def _cpu_tee_instance(server_id: str = "srv-1"):
    instance = MagicMock()
    instance.instance_id = "inst-1"
    instance.server_id = server_id
    return instance


def _cpu_server(attested_cert: str | None = _ATTESTED_PEM):
    server = MagicMock()
    server.self_registered = True
    server.compute_type = "cpu"
    server.attested_cert = attested_cert
    return server


def _db_returning(server):
    db = AsyncMock()
    result = MagicMock()
    result.scalar_one_or_none.return_value = server
    db.execute = AsyncMock(return_value=result)
    return db


@pytest.mark.asyncio
async def test_require_attested_client_cert_match_passes():
    """Matching client-cert pubkey hash == pinned attested cert -> allowed."""
    db = _db_returning(_cpu_server())
    with (
        patch("api.server.service.runtime_attestation_context_for_server"),
        patch.object(settings, "require_mtls_client_verify", True),
        patch("api.instance.util._get_client_certificate", return_value=MagicMock()),
        patch("api.instance.util.get_public_key_hash", return_value="samehash"),
        patch("api.instance.util.x509.load_pem_x509_certificate", return_value=MagicMock()),
    ):
        await require_attested_client_cert(db, MagicMock(), _cpu_tee_instance())


@pytest.mark.asyncio
async def test_require_attested_client_cert_mismatch_403():
    """A client cert whose pubkey hash != the pinned attested cert is rejected."""
    db = _db_returning(_cpu_server())
    with (
        patch("api.server.service.runtime_attestation_context_for_server"),
        patch.object(settings, "require_mtls_client_verify", True),
        patch("api.instance.util._get_client_certificate", return_value=MagicMock()),
        patch(
            "api.instance.util.get_public_key_hash",
            side_effect=["client_hash", "attested_hash"],
        ),
        patch("api.instance.util.x509.load_pem_x509_certificate", return_value=MagicMock()),
    ):
        with pytest.raises(HTTPException) as exc_info:
            await require_attested_client_cert(db, MagicMock(), _cpu_tee_instance())
        assert exc_info.value.status_code == 403


@pytest.mark.asyncio
async def test_require_attested_client_cert_jwt_only_rejected():
    """JWT-only caller (no verified mTLS client cert) is rejected -- the C-1 secret-exfil block."""
    db = _db_returning(_cpu_server())
    with (
        patch("api.server.service.runtime_attestation_context_for_server"),
        patch.object(settings, "require_mtls_client_verify", True),
        patch("api.instance.util._get_client_certificate", side_effect=NoClientCertError()),
    ):
        with pytest.raises(HTTPException) as exc_info:
            await require_attested_client_cert(db, MagicMock(), _cpu_tee_instance())
        assert exc_info.value.status_code == 403


@pytest.mark.asyncio
async def test_require_attested_client_cert_no_attested_cert_403():
    """A CPU-TEE server with no attested cert on record fails closed (cannot bind)."""
    db = _db_returning(_cpu_server(attested_cert=None))
    with (
        patch("api.server.service.runtime_attestation_context_for_server"),
        patch.object(settings, "require_mtls_client_verify", True),
    ):
        with pytest.raises(HTTPException) as exc_info:
            await require_attested_client_cert(db, MagicMock(), _cpu_tee_instance())
        assert exc_info.value.status_code == 403


@pytest.mark.asyncio
async def test_require_attested_client_cert_gpu_is_noop():
    """GPU / non-self-registered instances are bound by the quote dial, not this check -> no-op."""
    server = MagicMock()
    server.self_registered = False
    server.compute_type = "gpu"
    db = _db_returning(server)
    # Even with mTLS required and no client cert presented, the GPU path returns without raising.
    with patch.object(settings, "require_mtls_client_verify", True):
        await require_attested_client_cert(db, MagicMock(), _cpu_tee_instance())


@pytest.mark.asyncio
async def test_require_attested_client_cert_hard_fails_when_mtls_disabled():
    """Without an mTLS terminator (require_mtls_client_verify=false) the binding cannot be proven,
    so CPU-TEE secret endpoints must HARD-FAIL -- never warn-and-skip into unbound secret delivery."""
    db = _db_returning(_cpu_server())
    with (
        patch("api.server.service.runtime_attestation_context_for_server"),
        patch.object(settings, "require_mtls_client_verify", False),
    ):
        with pytest.raises(HTTPException) as exc_info:
            await require_attested_client_cert(db, MagicMock(), _cpu_tee_instance())
        assert exc_info.value.status_code == 403


def _active_cpu_pin(*, name="cpu-baremetal-tdx-current", mrtd="A" * 96):
    config = TeeMeasurementConfig(
        version="2.0.0-tdx-4vcpu",
        name=name,
        tee_type="tdx",
        provider="bare-metal",
        mrtd=mrtd,
        boot_rtmrs={f"RTMR{index}": chr(66 + index) * 96 for index in range(4)},
        runtime_rtmrs={f"RTMR{index}": chr(70 + index) * 96 for index in range(4)},
        expected_gpus=[],
        gpu_count=0,
        debug=False,
    )
    config.config_fingerprint = measurement_config_fingerprint(config)
    config.trust_set_fingerprint = measurement_trust_set_fingerprint([config])
    return config


def _issued_cpu_server(config):
    return SimpleNamespace(
        server_id="srv-issued",
        ip="192.168.1.1",
        miner_hotkey="miner_hotkey_123",
        name="issued-vm",
        is_tee=True,
        self_registered=True,
        compute_type="cpu",
        tee_type="tdx",
        host_id="l0-issued",
        storage_role=False,
        version=config.version,
        measurement_name=config.name,
        measurement_config_fingerprint=config.config_fingerprint,
        trust_set_fingerprint=config.trust_set_fingerprint,
        attested_cert=_ATTESTED_PEM,
        attested_cert_pubkey_hash="ab" * 32,
    )


def _post_issue_measurements(old_config, mutation):
    if mutation == "retired_name":
        return []
    if mutation == "changed_config":
        return [_active_cpu_pin(mrtd="9" * 96)]
    if mutation == "changed_trust":
        return [old_config, _active_cpu_pin(name="cpu-baremetal-tdx-added")]
    raise AssertionError(f"unknown mutation: {mutation}")


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "mutation",
    ["retired_name", "changed_config", "changed_trust"],
)
async def test_old_launch_token_is_revoked_before_self_registered_early_return(
    mutation,
):
    old_config = _active_cpu_pin()
    server = _issued_cpu_server(old_config)
    active = _post_issue_measurements(old_config, mutation)
    instance = SimpleNamespace(
        host=server.ip,
        server_id=server.server_id,
        chutes_version="0.6.0",
        extra={"e2e_pubkey": E2E_PUBKEY},
    )
    launch_config = SimpleNamespace(miner_hotkey=server.miner_hotkey)

    with patch(
        "api.server.service.settings",
        SimpleNamespace(tee_measurements=active),
    ):
        with pytest.raises(HTTPException) as exc_info:
            await verify_tee_chute(
                _db_returning(server),
                instance,
                launch_config,
                "deploy-issued",
                EXPECTED_NONCE,
                compute_type="cpu",
            )
    assert exc_info.value.status_code == 403
    assert "no longer active" in exc_info.value.detail


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "mutation",
    ["retired_name", "changed_config", "changed_trust"],
)
async def test_matching_issued_cert_is_revoked_before_secret_release(mutation):
    old_config = _active_cpu_pin()
    server = _issued_cpu_server(old_config)
    active = _post_issue_measurements(old_config, mutation)
    db = _db_returning(server)

    with (
        patch(
            "api.server.service.settings",
            SimpleNamespace(tee_measurements=active),
        ),
        patch.object(settings, "require_mtls_client_verify", True),
        patch("api.instance.util._get_client_certificate", return_value=MagicMock()),
        patch("api.instance.util.get_public_key_hash", return_value="samehash"),
        patch(
            "api.instance.util.x509.load_pem_x509_certificate",
            return_value=MagicMock(),
        ),
    ):
        with pytest.raises(HTTPException) as exc_info:
            await require_attested_client_cert(
                db,
                MagicMock(),
                _cpu_tee_instance(server.server_id),
            )
    assert exc_info.value.status_code == 403
    assert "no longer active" in exc_info.value.detail


# --------------------------------------------------------------------------------------------------
# create_provision_jwt: every token must carry a unique jti (single-use marker for the in-TEE
# chutes-provision service's replay registry).
# --------------------------------------------------------------------------------------------------


def test_create_provision_jwt_mints_unique_jti(tmp_path, monkeypatch):
    import subprocess

    import jwt as pyjwt

    from api.instance.util import create_provision_jwt

    key_path = tmp_path / "launch_key.pem"
    subprocess.run(
        [
            "openssl",
            "ecparam",
            "-name",
            "prime256v1",
            "-genkey",
            "-noout",
            "-out",
            str(key_path),
        ],
        check=True,
        capture_output=True,
    )
    monkeypatch.setattr(settings, "launch_config_private_key_bytes", key_path.read_bytes())

    first = pyjwt.decode(create_provision_jwt("chute-x"), options={"verify_signature": False})
    second = pyjwt.decode(create_provision_jwt("chute-x"), options={"verify_signature": False})

    assert first["purpose"] == "provision"
    assert first["server_id"] == "chute-x"
    assert isinstance(first["jti"], str) and len(first["jti"]) == 32
    # Replay protection only works if every mint is unique.
    assert first["jti"] != second["jti"]
