"""
Unit tests for api/server/service module.
Tests nonce management, attestation processing, server registration, and management operations.
"""

import json
import pytest
import secrets
from datetime import datetime, timezone
from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock, patch
from fastapi import HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.exc import IntegrityError

from api.server.service import (
    create_nonce,
    validate_and_consume_nonce,
    verify_quote,
    verify_server,
    process_boot_attestation,
    process_runtime_attestation,
    runtime_attestation_context_for_server,
    register_server,
    check_server_ownership,
    get_server_by_name,
    update_server_name,
    get_server_attestation_status,
    delete_server,
)
from api.server.schemas import (
    Server,
    ServerAttestation,
    BootAttestation,
    BootAttestationArgs,
    BootAttestationNonceContext,
    RuntimeAttestationArgs,
    ServerArgs,
)
from api.server.quote import BootTdxQuote, RuntimeTdxQuote, TdxVerificationResult
from api.server.exceptions import (
    InvalidQuoteError,
    MeasurementMismatchError,
    NonceError,
    ServerNotFoundError,
    ServerRegistrationError,
    InvalidSignatureError,
)
from api.config import (
    TeeMeasurementConfig,
    measurement_config_fingerprint,
    measurement_trust_set_fingerprint,
)
from api.constants import NoncePurpose
from api.node.schemas import NodeArgs
from tests.fixtures.gpus import TEST_GPU_NONCE

TEST_SERVER_IP = "127.0.0.1"
TEST_NONCE = TEST_GPU_NONCE


def _tee_measurements_for_service_tests():
    """TeeMeasurementConfig list matching sample_boot_quote and sample_runtime_quote."""
    return [
        TeeMeasurementConfig(
            version="1",
            mrtd="a" * 96,
            name="test",
            rtmr0="b" * 96,
            rtmr1="c" * 96,
            rtmr2="d" * 96,
            runtime_rtmr3="e" * 96,
            expected_gpus=["h200"],
            gpu_count=1,
            provider="bare-metal",
            tee_type="tdx",
        ),
    ]


@pytest.fixture
def mock_redis_client():
    """Mock Redis client for nonce operations."""
    redis_mock = AsyncMock()
    redis_mock.setex = AsyncMock(return_value=True)
    redis_mock.get = AsyncMock()
    redis_mock.delete = AsyncMock(return_value=1)
    return redis_mock


@pytest.fixture(autouse=True)
def mock_settings(mock_redis_client):
    """Mock settings with Redis client - auto-applied to all tests."""
    settings = Mock()
    settings.redis_client = mock_redis_client
    settings.tee_measurements = _tee_measurements_for_service_tests()
    # Real string (a Mock breaks semver comparison in process_boot_attestation's version gate).
    settings.tee_minimum_boot_version = "0.0.0"

    with (
        patch("api.server.service.settings", settings),
        patch("api.server.util.settings", settings),
    ):
        yield settings


TEST_CERT_HASH = "test_cert_hash"


@pytest.fixture(autouse=True)
def mock_util_functions():
    """Mock utility functions that are consistently used."""
    with (
        patch("api.server.service.generate_nonce", return_value=TEST_GPU_NONCE) as mock_gen,
        patch("api.server.service.get_nonce_expiry_seconds", return_value=600) as mock_exp,
        patch(
            "api.server.util.extract_report_data",
            return_value=(TEST_GPU_NONCE, TEST_CERT_HASH),
        ) as mock_extract,
        patch("api.server.service.verify_gpu_evidence") as mock_verify_gpu,
    ):
        yield {
            "generate_nonce": mock_gen,
            "get_nonce_expiry_seconds": mock_exp,
            "extract_report_data": mock_extract,
            "mock_verify_gpu": mock_verify_gpu,
        }


@pytest.fixture(autouse=True)
def mock_sqlalchemy_func():
    """Mock SQLAlchemy func.now() - auto-applied to all tests."""
    with patch("api.server.service.func") as mock_func:
        mock_func.now.return_value = datetime.now(timezone.utc)
        yield mock_func


@pytest.fixture(autouse=True)
def mock_attestation_subject():
    """Subject persistence has dedicated protocol tests; isolate broad service tests."""

    with patch(
        "api.server.service._ensure_attestation_subject",
        new_callable=AsyncMock,
    ) as ensure_subject:
        yield ensure_subject


@pytest.fixture
def mock_db_session():
    """Mock database session."""
    session = AsyncMock(spec=AsyncSession)
    session.add = Mock()
    session.commit = AsyncMock()
    session.rollback = AsyncMock()
    session.refresh = AsyncMock()
    session.execute = AsyncMock()
    return session


def _server_lock_result(server):
    result = Mock()
    result.scalar_one.return_value = server
    return result


def _latest_added_attempt_result(session):
    """Return whichever ServerAttestation this test just durably allocated."""

    result = Mock()
    result.scalar_one_or_none.side_effect = lambda: session.add.call_args.args[0]
    return result


# Test data fixtures


@pytest.fixture
def sample_boot_quote():
    """Sample BootTdxQuote for testing."""
    return BootTdxQuote(
        version=4,
        att_key_type=2,
        tee_type=0x81,
        mrtd="a" * 96,
        rtmr0="b" * 96,
        rtmr1="c" * 96,
        rtmr2="d" * 96,
        rtmr3="0" * 96,
        report_data=None,
        user_data="746573745f6e6f6e63655f31323300000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",  # TEST_NONCE
        platform_id="0" * 32,
        raw_quote_size=4096,
        parsed_at=datetime.now(timezone.utc).isoformat(),
        raw_bytes=b"dummy_boot_quote_bytes",
    )


@pytest.fixture
def sample_runtime_quote():
    """Sample RuntimeTdxQuote for testing."""
    return RuntimeTdxQuote(
        version=4,
        att_key_type=2,
        tee_type=0x81,
        mrtd="a" * 96,
        rtmr0="b" * 96,
        rtmr1="c" * 96,
        rtmr2="d" * 96,
        rtmr3="e" * 96,
        report_data=None,
        user_data="72756e74696d655f6e6f6e63655f34353600000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",  # runtime_nonce_456
        platform_id="0" * 32,
        raw_quote_size=4096,
        parsed_at=datetime.now(timezone.utc).isoformat(),
        raw_bytes=b"dummy_runtime_quote_bytes",
    )


@pytest.fixture
def sample_verification_result():
    """Sample TdxVerificationResult for testing."""
    return TdxVerificationResult(
        mrtd="a" * 96,
        rtmr0="b" * 96,
        rtmr1="c" * 96,
        rtmr2="d" * 96,
        rtmr3="0" * 96,
        user_data="test_data",
        parsed_at=datetime.now(timezone.utc),
        status="UpToDate",
        advisory_ids=[],
        td_attributes="0000001000000000",
    )


@pytest.fixture
def boot_attestation_args(valid_quote_base64):
    """Sample BootAttestationArgs for testing."""
    return BootAttestationArgs(
        quote=valid_quote_base64,
        server_id="test-server-123",
    )


@pytest.fixture
def runtime_attestation_args(valid_quote_base64):
    """Sample RuntimeAttestationArgs for testing."""
    return RuntimeAttestationArgs(
        quote=valid_quote_base64  # base64 encoded "runtime_quote_data"
    )


def _sample_node_args():
    """Minimal NodeArgs for ServerArgs.gpus (matches tee_measurements expected_gpus h200)."""
    return NodeArgs(
        uuid="gpu-uuid-1",
        name="GPU 0",
        memory=80 * 1024,
        clock_rate=1.41,
        device_index=0,
        gpu_identifier="h200",
        verification_host=TEST_SERVER_IP,
        verification_port=443,
    )


@pytest.fixture
def server_args():
    """Sample ServerArgs for testing."""
    return ServerArgs(
        id="test-server-123",
        host=TEST_SERVER_IP,
        name="test-vm-name",
        gpus=[_sample_node_args()],
    )


@pytest.fixture
def sample_server():
    """Sample Server object for testing."""
    measurement = _tee_measurements_for_service_tests()[0]
    server = Server(
        server_id="test-server-123",
        ip=TEST_SERVER_IP,
        miner_hotkey="5FTestHotkey123",
        name="test-vm",
        is_tee=True,
        storage_role=False,
        compute_type="gpu",
        tee_type="tdx",
        version="1",
        measurement_name="test",
        measurement_config_fingerprint=measurement_config_fingerprint(measurement),
        trust_set_fingerprint=measurement_trust_set_fingerprint([measurement]),
        attested_cert="-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----",
        attested_cert_pubkey_hash=TEST_CERT_HASH,
        created_at=datetime.now(timezone.utc),
        updated_at=None,
    )
    return server


@pytest.fixture
def runtime_nonce_context(sample_server):
    return runtime_attestation_context_for_server(sample_server)


@pytest.fixture
def boot_nonce_context(sample_server):
    return BootAttestationNonceContext(
        server_id=sample_server.server_id,
        miner_hotkey=sample_server.miner_hotkey,
        vm_name=sample_server.name,
        cert_hash=TEST_CERT_HASH,
        storage_role=False,
        allowed_volumes=["storage", "tdx-cache"],
    )


@pytest.fixture
def sample_server_attestation():
    """Sample ServerAttestation object for testing."""
    measurement = _tee_measurements_for_service_tests()[0]
    return ServerAttestation(
        attestation_id="server-attest-123",
        server_id="test-server-123",
        quote_data="cnVudGltZV9xdW90ZV9kYXRh",
        verification_error=None,
        measurement_version="1",
        measurement_name="test",
        measurement_config_fingerprint=measurement_config_fingerprint(measurement),
        trust_set_fingerprint=measurement_trust_set_fingerprint([measurement]),
        created_at=datetime.now(timezone.utc),
        verified_at=datetime.now(timezone.utc),
    )


# Mock verification functions as fixtures


@pytest.fixture
def mock_verify_quote_signature(sample_verification_result):
    """Mock verify_quote_signature function."""
    with patch(
        "api.server.util.verify_quote_signature",
        return_value=sample_verification_result,
    ) as mock:
        yield mock


@pytest.fixture
def mock_verify_measurements():
    """Mock verify_measurements function."""
    with patch("api.server.util.verify_measurements", return_value=True) as mock:
        yield mock


@pytest.fixture
def mock_validate_nonce():
    """Mock validate_and_consume_nonce function."""
    with patch("api.server.service.validate_and_consume_nonce") as mock:
        yield mock


@pytest.fixture
def mock_quote_parsing(sample_boot_quote, sample_runtime_quote):
    """Mock quote parsing functions."""
    with patch(
        "api.server.service.BootTdxQuote.from_base64", return_value=sample_boot_quote
    ) as mock_boot:
        with patch(
            "api.server.service.build_runtime_quote", return_value=sample_runtime_quote
        ) as mock_runtime:
            yield {"boot": mock_boot, "runtime": mock_runtime}


# Nonce Management Tests


@pytest.mark.asyncio
async def test_create_nonce(mock_settings):
    """Test creating a boot nonce."""
    result = await create_nonce(TEST_SERVER_IP, NoncePurpose.BOOT)

    assert result["nonce"] == TEST_NONCE
    assert "expires_at" in result

    # Verify Redis operations (value is JSON: server_ip + purpose)
    expected_value = json.dumps(
        {
            "server_ip": TEST_SERVER_IP,
            "purpose": NoncePurpose.BOOT.value,
            "context": None,
        }
    )
    mock_settings.redis_client.setex.assert_called_once_with(
        f"nonce:{TEST_NONCE}", 600, expected_value
    )


@pytest.mark.asyncio
async def test_validate_and_consume_nonce_success(mock_settings):
    """Test successful nonce validation and consumption."""
    mock_settings.redis_client.getdel.return_value = json.dumps(
        {"server_ip": TEST_SERVER_IP, "purpose": NoncePurpose.BOOT.value}
    ).encode()
    await validate_and_consume_nonce(TEST_GPU_NONCE, TEST_SERVER_IP, NoncePurpose.BOOT)

    mock_settings.redis_client.getdel.assert_called_once_with(f"nonce:{TEST_NONCE}")


@pytest.mark.asyncio
async def test_validate_and_consume_nonce_not_found(mock_settings):
    """Test nonce validation when nonce doesn't exist (or was already consumed)."""
    mock_settings.redis_client.getdel.return_value = None

    with pytest.raises(NonceError, match="Nonce not found or expired"):
        await validate_and_consume_nonce("invalid_nonce", TEST_SERVER_IP, NoncePurpose.BOOT)


@pytest.mark.asyncio
async def test_validate_and_consume_nonce_server_mismatch(mock_settings):
    """Test nonce validation with wrong server ID."""
    mock_settings.redis_client.getdel.return_value = json.dumps(
        {"server_ip": TEST_SERVER_IP, "purpose": NoncePurpose.BOOT.value}
    ).encode()

    with pytest.raises(NonceError, match="Nonce server mismatch"):
        await validate_and_consume_nonce(TEST_GPU_NONCE, "192.168.0.1", NoncePurpose.BOOT)


# Quote Verification Tests


@pytest.mark.asyncio
async def test_verify_quote_success(
    sample_boot_quote,
    mock_validate_nonce,
    mock_verify_quote_signature,
    mock_verify_measurements,
):
    """Test successful quote verification."""
    result = await verify_quote(sample_boot_quote, TEST_NONCE, TEST_CERT_HASH)

    assert isinstance(result, TdxVerificationResult)
    mock_verify_quote_signature.assert_called_once_with(sample_boot_quote)
    mock_verify_measurements.assert_called_once_with(sample_boot_quote)


@pytest.mark.asyncio
async def test_verify_quote_nonce_failure(sample_boot_quote, mock_validate_nonce):
    """Test quote verification with nonce failure."""
    mock_validate_nonce.side_effect = NonceError("Invalid nonce")

    with pytest.raises(NonceError):
        await verify_quote(sample_boot_quote, "INVALID_NONCE", TEST_CERT_HASH)


@pytest.mark.asyncio
async def test_verify_quote_signature_failure(
    sample_boot_quote, mock_validate_nonce, mock_verify_quote_signature
):
    """Test quote verification with signature failure."""
    mock_verify_quote_signature.side_effect = InvalidSignatureError("Invalid signature")

    with pytest.raises(InvalidSignatureError):
        await verify_quote(sample_boot_quote, TEST_NONCE, TEST_CERT_HASH)


@pytest.mark.asyncio
async def test_verify_quote_measurement_failure(
    sample_boot_quote,
    mock_validate_nonce,
    mock_verify_quote_signature,
    mock_verify_measurements,
):
    """Test quote verification with measurement failure."""
    mock_verify_measurements.side_effect = MeasurementMismatchError("MRTD mismatch")

    with pytest.raises(MeasurementMismatchError):
        await verify_quote(sample_boot_quote, TEST_NONCE, TEST_CERT_HASH)


# Boot Attestation Tests


@pytest.mark.asyncio
async def test_process_boot_attestation_success(
    mock_db_session,
    boot_attestation_args,
    boot_nonce_context,
    sample_server,
    mock_quote_parsing,
    mock_verify_quote_signature,
    mock_verify_measurements,
    mock_validate_nonce,
):
    """Test successful boot attestation processing."""
    mock_db_session.get.return_value = sample_server
    # Setup mocks for verification success
    with patch("api.server.service.verify_quote") as mock_verify:
        mock_verify.return_value = TdxVerificationResult(
            mrtd="a" * 96,
            rtmr0="b" * 96,
            rtmr1="c" * 96,
            rtmr2="d" * 96,
            rtmr3="e" * 96,
            user_data="test",
            parsed_at=datetime.now(timezone.utc),
            status="UpToDate",
            advisory_ids=[],
            td_attributes="0000001000000000",
        )

        # Mock database refresh to set attestation_id
        def mock_refresh(obj):
            obj.attestation_id = "boot-attest-123"
            obj.verified_at = datetime.now(timezone.utc)

        mock_db_session.refresh.side_effect = mock_refresh

        with (
            patch(
                "api.server.service.generate_luks_quote_nonce",
                new_callable=AsyncMock,
                return_value="test-luks-nonce",
            ),
            patch(
                "api.server.service._handle_boot_version_update",
                new_callable=AsyncMock,
            ),
        ):
            result = await process_boot_attestation(
                mock_db_session,
                TEST_SERVER_IP,
                boot_attestation_args,
                TEST_NONCE,
                boot_nonce_context,
                TEST_CERT_HASH,
            )

        assert result == "test-luks-nonce"

        # Verify database operations
        mock_db_session.add.assert_called_once()
        mock_db_session.commit.assert_called_once()


@pytest.mark.asyncio
async def test_process_boot_attestation_quote_failure(
    mock_db_session,
    boot_attestation_args,
    boot_nonce_context,
    sample_server,
):
    """Test boot attestation with quote parsing failure."""
    mock_db_session.get.return_value = sample_server
    with patch(
        "api.server.service.BootTdxQuote.from_base64",
        side_effect=InvalidQuoteError("Invalid quote"),
    ):
        with pytest.raises(InvalidQuoteError):
            await process_boot_attestation(
                mock_db_session,
                TEST_SERVER_IP,
                boot_attestation_args,
                TEST_NONCE,
                boot_nonce_context,
                TEST_CERT_HASH,
            )


@pytest.mark.asyncio
async def test_process_boot_attestation_verification_failure(
    mock_db_session,
    boot_attestation_args,
    boot_nonce_context,
    sample_boot_quote,
    sample_server,
):
    """Test boot attestation with verification failure."""
    mock_db_session.get.return_value = sample_server
    with patch("api.server.service.BootTdxQuote.from_base64", return_value=sample_boot_quote):
        with patch(
            "api.server.service.verify_quote",
            side_effect=MeasurementMismatchError("Measurement failed"),
        ):
            with pytest.raises(MeasurementMismatchError):
                await process_boot_attestation(
                    mock_db_session,
                    TEST_SERVER_IP,
                    boot_attestation_args,
                    TEST_NONCE,
                    boot_nonce_context,
                    TEST_CERT_HASH,
                )

            # Should still create failed attestation record
            mock_db_session.add.assert_called_once()
            mock_db_session.commit.assert_called_once()


# Runtime Attestation Tests


@pytest.mark.asyncio
async def test_process_runtime_attestation_success(
    mock_db_session,
    runtime_attestation_args,
    sample_server,
    sample_runtime_quote,
    runtime_nonce_context,
):
    """Test successful runtime attestation processing."""
    server_id = "test-server-123"
    miner_hotkey = "5FTestHotkey123"
    mock_db_session.execute.return_value = _latest_added_attempt_result(mock_db_session)

    with patch("api.server.service.check_server_ownership", return_value=sample_server):
        with patch(
            "api.server.service.build_runtime_quote",
            return_value=sample_runtime_quote,
        ):
            with patch("api.server.service.verify_quote") as mock_verify:
                mock_verify.return_value = TdxVerificationResult(
                    mrtd="a" * 96,
                    rtmr0="d" * 96,
                    rtmr1="e" * 96,
                    rtmr2="f" * 96,
                    rtmr3="0" * 96,
                    user_data="test",
                    parsed_at=datetime.now(timezone.utc),
                    status="UpToDate",
                    advisory_ids=[],
                    td_attributes="0000001000000000",
                )

                def mock_refresh(obj):
                    obj.attestation_id = "runtime-attest-123"
                    obj.verified_at = datetime.now(timezone.utc)

                mock_db_session.refresh.side_effect = mock_refresh

                result = await process_runtime_attestation(
                    mock_db_session,
                    server_id,
                    TEST_SERVER_IP,
                    runtime_attestation_args,
                    miner_hotkey,
                    TEST_NONCE,
                    TEST_CERT_HASH,
                    runtime_nonce_context,
                )

            assert result["attestation_id"] == "runtime-attest-123"
            assert result["status"] == "verified"
            assert "verified_at" in result

            mock_db_session.add.assert_called_once()
            assert mock_db_session.commit.await_count == 3
            mock_db_session.rollback.assert_not_awaited()
            assert mock_db_session.execute.await_count == 4


@pytest.mark.asyncio
async def test_process_runtime_attestation_server_not_found(
    mock_db_session, runtime_attestation_args, runtime_nonce_context
):
    """Test runtime attestation when server is not found."""
    server_id = "nonexistent-server"
    miner_hotkey = "5FTestHotkey123"

    with patch(
        "api.server.service.check_server_ownership",
        side_effect=ServerNotFoundError(server_id),
    ):
        with pytest.raises(ServerNotFoundError):
            await process_runtime_attestation(
                mock_db_session,
                server_id,
                TEST_SERVER_IP,
                runtime_attestation_args,
                miner_hotkey,
                TEST_NONCE,
                TEST_CERT_HASH,
                runtime_nonce_context,
            )


# Server Registration Tests


@pytest.mark.asyncio
async def test_register_server_success(mock_db_session, server_args, sample_server):
    """Test successful server registration."""
    miner_hotkey = "5FTestHotkey123"

    with patch("api.server.service._track_server", return_value=sample_server):
        with patch("api.server.service._track_nodes", new_callable=AsyncMock):
            with patch(
                "api.server.service.verify_server",
                new_callable=AsyncMock,
                return_value="1.0.0",
            ):
                await register_server(mock_db_session, server_args, miner_hotkey)

    assert sample_server.version == "1.0.0"
    mock_db_session.commit.assert_called()


@pytest.mark.asyncio
async def test_register_server_integrity_error(mock_db_session, server_args, sample_server):
    """Test server registration handles IntegrityError from _track_nodes."""
    miner_hotkey = "5FTestHotkey123"

    with patch("api.server.service._track_server", return_value=sample_server):
        with patch(
            "api.server.service._track_nodes",
            new_callable=AsyncMock,
            side_effect=IntegrityError("Duplicate key", None, None),
        ):
            with patch(
                "api.server.service.verify_server",
                new_callable=AsyncMock,
                return_value="1.0.0",
            ):
                with pytest.raises(ServerRegistrationError):
                    await register_server(mock_db_session, server_args, miner_hotkey)

    mock_db_session.rollback.assert_called_once()


# Server Ownership Tests


@pytest.mark.asyncio
async def test_check_server_ownership_success(mock_db_session, sample_server):
    """Test successful server ownership check."""
    server_id = "test-server-123"
    miner_hotkey = "5FTestHotkey123"

    # Mock database query result
    mock_result = Mock()
    mock_result.scalar_one_or_none.return_value = sample_server
    mock_db_session.execute.return_value = mock_result

    result = await check_server_ownership(mock_db_session, server_id, miner_hotkey)

    assert result == sample_server
    mock_db_session.execute.assert_called_once()


@pytest.mark.asyncio
async def test_check_server_ownership_not_found(mock_db_session):
    """Test server ownership check when server not found."""
    server_id = "nonexistent-server"
    miner_hotkey = "5FTestHotkey123"

    mock_result = Mock()
    mock_result.scalar_one_or_none.return_value = None
    mock_db_session.execute.return_value = mock_result

    with pytest.raises(ServerNotFoundError):
        await check_server_ownership(mock_db_session, server_id, miner_hotkey)


# Server Attestation Status Tests


@pytest.mark.asyncio
async def test_get_server_attestation_status_with_attestation(
    mock_db_session, sample_server, sample_server_attestation
):
    """Test getting server attestation status with existing attestation."""
    server_id = "test-server-123"
    miner_hotkey = "5FTestHotkey123"

    with patch("api.server.service.check_server_ownership", return_value=sample_server):
        mock_result = Mock()
        mock_result.scalar_one_or_none.return_value = sample_server_attestation
        mock_db_session.execute.return_value = mock_result

        result = await get_server_attestation_status(mock_db_session, server_id, miner_hotkey)

        assert result["server_id"] == server_id
        assert result["attestation_status"] == "verified"
        assert (
            result["last_attestation"]["attestation_id"] == sample_server_attestation.attestation_id
        )


@pytest.mark.asyncio
async def test_get_server_attestation_status_no_attestation(mock_db_session, sample_server):
    """Test getting server attestation status with no attestations."""
    server_id = "test-server-123"
    miner_hotkey = "5FTestHotkey123"

    with patch("api.server.service.check_server_ownership", return_value=sample_server):
        mock_result = Mock()
        mock_result.scalar_one_or_none.return_value = None
        mock_db_session.execute.return_value = mock_result

        result = await get_server_attestation_status(mock_db_session, server_id, miner_hotkey)

        assert result["server_id"] == server_id
        assert result["attestation_status"] == "never_attested"
        assert result["last_attestation"] is None


# Server Deletion Tests


def _empty_server_retirement_result():
    result = Mock()
    result.scalar_one_or_none.return_value = None
    result.scalars.return_value.all.return_value = []
    result.unique.return_value.scalars.return_value.all.return_value = []
    return result


@pytest.mark.asyncio
async def test_delete_server_success(mock_db_session, sample_server):
    """CPU servers retain the generic deletion behavior."""
    server_id = "test-server-123"
    miner_hotkey = "5FTestHotkey123"
    sample_server.compute_type = "cpu"

    with patch("api.server.service.check_server_ownership", return_value=sample_server):
        mock_db_session.execute.return_value = _empty_server_retirement_result()
        result = await delete_server(mock_db_session, server_id, miner_hotkey)

        assert result is True
        mock_db_session.delete.assert_called_once()
        mock_db_session.commit.assert_called_once()


@pytest.mark.asyncio
async def test_delete_gpu_server_requires_explicit_decommission(
    mock_db_session, sample_server
):
    sample_server.compute_type = "gpu"
    with (
        patch("api.server.service.check_server_ownership", return_value=sample_server),
        pytest.raises(HTTPException, match="explicit decommission endpoint") as exc,
    ):
        await delete_server(mock_db_session, sample_server.server_id, sample_server.miner_hotkey)

    assert exc.value.status_code == 409
    mock_db_session.delete.assert_not_called()
    mock_db_session.commit.assert_not_called()


@pytest.mark.asyncio
async def test_delete_server_not_found(mock_db_session):
    """Test server deletion when server not found."""
    server_id = "nonexistent-server"
    miner_hotkey = "5FTestHotkey123"

    with patch(
        "api.server.service.check_server_ownership",
        side_effect=ServerNotFoundError(server_id),
    ):
        with pytest.raises(ServerNotFoundError):
            await delete_server(mock_db_session, server_id, miner_hotkey)


# update_server_vm_name (sync server names) tests


@pytest.mark.asyncio
async def test_get_server_by_name_success(mock_db_session, sample_server):
    """Test get_server_by_name returns server when found."""
    miner_hotkey = sample_server.miner_hotkey
    server_name = sample_server.name
    mock_result = Mock()
    mock_result.scalar_one_or_none.return_value = sample_server
    mock_db_session.execute.return_value = mock_result

    result = await get_server_by_name(mock_db_session, miner_hotkey, server_name)

    assert result == sample_server


@pytest.mark.asyncio
async def test_get_server_by_name_not_found(mock_db_session):
    """Test get_server_by_miner_and_vm raises when server not found."""
    mock_result = Mock()
    mock_result.scalar_one_or_none.return_value = None
    mock_db_session.execute.return_value = mock_result

    with pytest.raises(ServerNotFoundError) as exc_info:
        await get_server_by_name(mock_db_session, "5FTestHotkey123", "nonexistent-vm")
    assert "nonexistent-vm" in str(exc_info.value.detail)


@pytest.mark.asyncio
async def test_update_server_name_success(mock_db_session, sample_server):
    """Test update_server_name updates name and returns server."""
    server_id = sample_server.server_id
    miner_hotkey = sample_server.miner_hotkey
    new_name = "my-actual-vm-name"

    with patch("api.server.service.check_server_ownership", return_value=sample_server):
        result = await update_server_name(mock_db_session, miner_hotkey, server_id, new_name)

    assert result.name == new_name
    mock_db_session.commit.assert_called_once()
    mock_db_session.refresh.assert_called_once_with(sample_server)


@pytest.mark.asyncio
async def test_update_server_name_idempotent(mock_db_session, sample_server):
    """Test update_server_name is idempotent when name unchanged."""
    server_id = sample_server.server_id
    miner_hotkey = sample_server.miner_hotkey
    existing_name = sample_server.name

    with patch("api.server.service.check_server_ownership", return_value=sample_server):
        result = await update_server_name(mock_db_session, miner_hotkey, server_id, existing_name)

    assert result == sample_server
    mock_db_session.commit.assert_not_called()
    mock_db_session.refresh.assert_not_called()


@pytest.mark.asyncio
async def test_update_server_name_not_found(mock_db_session):
    """Test update_server_vm_name raises when server not found."""
    with patch(
        "api.server.service.check_server_ownership",
        side_effect=ServerNotFoundError("nonexistent-server"),
    ):
        with pytest.raises(ServerNotFoundError):
            await update_server_name(
                mock_db_session,
                "5FTestHotkey123",
                "nonexistent-server",
                "new-vm-name",
            )


@pytest.mark.asyncio
async def test_update_server_name_conflict(mock_db_session, sample_server):
    """Test update_server_vm_name raises 409 when vm_name already in use."""
    from fastapi import HTTPException

    server_id = sample_server.server_id
    miner_hotkey = sample_server.miner_hotkey
    new_vm_name = "taken-vm-name"

    with patch("api.server.service.check_server_ownership", return_value=sample_server):
        mock_db_session.commit.side_effect = IntegrityError("conflict", None, None)
        with pytest.raises(HTTPException) as exc_info:
            await update_server_name(mock_db_session, miner_hotkey, server_id, new_vm_name)
    assert exc_info.value.status_code == 409
    mock_db_session.rollback.assert_called_once()


# Edge Cases and Error Handling Tests


@pytest.mark.asyncio
async def test_create_nonce_redis_failure(mock_settings):
    """Test nonce creation when Redis fails."""
    mock_settings.redis_client.setex.side_effect = Exception("Redis connection failed")

    with pytest.raises(Exception):
        await create_nonce(TEST_SERVER_IP, NoncePurpose.BOOT)


@pytest.mark.asyncio
async def test_validate_nonce_invalid_format(mock_settings):
    """Test nonce validation when Redis value can't be decoded as JSON."""
    mock_settings.redis_client.getdel.return_value = b"\xff\xfe\xfd"

    with pytest.raises(NonceError, match="Invalid nonce format"):
        await validate_and_consume_nonce(TEST_GPU_NONCE, TEST_SERVER_IP, NoncePurpose.BOOT)


@pytest.mark.asyncio
async def test_register_server_general_exception(mock_db_session, server_args, sample_server):
    """Test server registration handles unexpected exceptions."""
    miner_hotkey = "5FTestHotkey123"

    with patch("api.server.service._track_server", return_value=sample_server):
        with patch(
            "api.server.service._track_nodes",
            new_callable=AsyncMock,
            side_effect=Exception("Database error"),
        ):
            with patch(
                "api.server.service.verify_server",
                new_callable=AsyncMock,
                return_value="1.0.0",
            ):
                with pytest.raises(ServerRegistrationError):
                    await register_server(mock_db_session, server_args, miner_hotkey)

    mock_db_session.rollback.assert_called_once()


# Parameterized Tests
@pytest.mark.parametrize(
    "redis_value,expected_error",
    [
        (None, "Nonce not found or expired"),
        (TEST_SERVER_IP, "Invalid nonce format"),
        # A legacy bare-string nonce value (no purpose) is now rejected fail-closed rather than
        # interpreted as a server IP -- a purpose-less nonce could otherwise be replayed cross-purpose.
        (
            json.dumps("192.168.0.1").encode(),
            "Invalid nonce format \\(missing purpose\\)",
        ),
    ],
)
@pytest.mark.asyncio
async def test_nonce_validation_error_cases(mock_settings, redis_value, expected_error):
    """Test various nonce validation error scenarios."""
    mock_settings.redis_client.getdel.return_value = redis_value

    with pytest.raises(NonceError, match=expected_error):
        await validate_and_consume_nonce(TEST_GPU_NONCE, TEST_SERVER_IP, NoncePurpose.BOOT)


# Integration-style Tests (Testing Multiple Functions Together)


@pytest.mark.asyncio
async def test_full_boot_flow_end_to_end(
    mock_db_session,
    mock_settings,
    mock_verify_measurements,
    boot_nonce_context,
    sample_server,
):
    """Test complete boot attestation flow."""
    mock_db_session.get.return_value = sample_server
    # Step 1: Create nonce
    mock_settings.redis_client.get.return_value = json.dumps(
        {"server_ip": TEST_SERVER_IP, "purpose": NoncePurpose.BOOT.value}
    ).encode()

    nonce_result = await create_nonce(TEST_SERVER_IP, NoncePurpose.BOOT)
    assert nonce_result["nonce"] == TEST_GPU_NONCE

    # Step 2: Create quote with nonce
    boot_quote = BootTdxQuote(
        version=4,
        att_key_type=2,
        tee_type=0x81,
        mrtd="a" * 96,
        rtmr0="b" * 96,
        rtmr1="c" * 96,
        rtmr2="d" * 96,
        rtmr3="0" * 96,
        report_data=None,
        user_data="626f6f745f6e6f6e63655f31323300000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",  # boot_nonce_123
        platform_id="0" * 32,
        raw_quote_size=4096,
        parsed_at=datetime.now(timezone.utc).isoformat(),
        raw_bytes=b"boot_quote",
    )

    # Step 3: Process attestation
    args = BootAttestationArgs(
        quote="dGVzdF9xdW90ZV9kYXRh",
        server_id=sample_server.server_id,
    )

    with patch("api.server.service.BootTdxQuote.from_base64", return_value=boot_quote):
        with patch("api.server.util.verify_quote_signature") as mock_verify:
            mock_verify.return_value = TdxVerificationResult(
                mrtd="a" * 96,
                rtmr0="b" * 96,
                rtmr1="c" * 96,
                rtmr2="d" * 96,
                rtmr3="0" * 96,
                user_data="test",
                parsed_at=datetime.now(timezone.utc),
                status="UpToDate",
                advisory_ids=[],
                td_attributes="0000001000000000",
            )

            def mock_refresh(obj):
                obj.attestation_id = "boot-attest-123"
                obj.verified_at = datetime.now(timezone.utc)

            mock_db_session.refresh.side_effect = mock_refresh

            with (
                patch(
                    "api.server.service.generate_luks_quote_nonce",
                    new_callable=AsyncMock,
                    return_value="test-luks-nonce",
                ),
                patch(
                    "api.server.service._handle_boot_version_update",
                    new_callable=AsyncMock,
                ),
            ):
                result = await process_boot_attestation(
                    mock_db_session,
                    TEST_SERVER_IP,
                    args,
                    TEST_NONCE,
                    boot_nonce_context,
                    TEST_CERT_HASH,
                )

            assert result == "test-luks-nonce"


@pytest.mark.asyncio
async def test_full_runtime_flow_end_to_end(
    mock_db_session,
    mock_settings,
    sample_server,
    mock_verify_measurements,
    runtime_nonce_context,
):
    """Test complete runtime attestation flow."""
    server_id = "test-server-123"
    miner_hotkey = "5FTestHotkey123"
    mock_db_session.execute.return_value = _latest_added_attempt_result(mock_db_session)

    # Step 1: Create runtime nonce
    mock_settings.redis_client.get.return_value = json.dumps(
        {"server_ip": TEST_SERVER_IP, "purpose": NoncePurpose.RUNTIME.value}
    ).encode()

    nonce_result = await create_nonce(TEST_SERVER_IP, NoncePurpose.RUNTIME)
    assert nonce_result["nonce"] == TEST_NONCE

    # Step 2: Process runtime attestation
    runtime_quote = RuntimeTdxQuote(
        version=4,
        att_key_type=2,
        tee_type=0x81,
        mrtd="a" * 96,
        rtmr0="b" * 96,
        rtmr1="c" * 96,
        rtmr2="d" * 96,
        rtmr3="e" * 96,
        report_data=None,
        user_data="72756e74696d655f6e6f6e63655f34353600000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",  # runtime_nonce_456
        platform_id="0" * 32,
        raw_quote_size=4096,
        parsed_at=datetime.now(timezone.utc).isoformat(),
        raw_bytes=b"runtime_quote",
    )

    args = RuntimeAttestationArgs(quote="cnVudGltZV9xdW90ZV9kYXRh")

    with patch("api.server.service.check_server_ownership", return_value=sample_server):
        with patch("api.server.service.build_runtime_quote", return_value=runtime_quote):
            with patch("api.server.util.verify_quote_signature") as mock_verify:
                mock_verify.return_value = TdxVerificationResult(
                    mrtd="a" * 96,
                    rtmr0="b" * 96,
                    rtmr1="c" * 96,
                    rtmr2="d" * 96,
                    rtmr3="e" * 96,
                    user_data="test",
                    parsed_at=datetime.now(timezone.utc),
                    status="UpToDate",
                    advisory_ids=[],
                    td_attributes="0000001000000000",
                )

                def mock_refresh(obj):
                    obj.attestation_id = "runtime-attest-123"
                    obj.verified_at = datetime.now(timezone.utc)

                mock_db_session.refresh.side_effect = mock_refresh

                result = await process_runtime_attestation(
                    mock_db_session,
                    server_id,
                    TEST_SERVER_IP,
                    args,
                    miner_hotkey,
                    TEST_NONCE,
                    TEST_CERT_HASH,
                    runtime_nonce_context,
                )

                assert result["status"] == "verified"
                assert result["attestation_id"] == "runtime-attest-123"
                assert mock_db_session.commit.await_count == 3
                mock_db_session.rollback.assert_not_awaited()
                assert mock_db_session.execute.await_count == 4


@pytest.mark.asyncio
async def test_server_lifecycle_flow(mock_db_session, sample_server, server_args):
    """Test complete server lifecycle: register -> check ownership -> delete."""
    miner_hotkey = "5FTestHotkey123"

    with patch("api.server.service._track_server", return_value=sample_server):
        with patch("api.server.service._track_nodes", new_callable=AsyncMock):
            with patch(
                "api.server.service.verify_server",
                new_callable=AsyncMock,
                return_value="1.0.0",
            ):
                await register_server(mock_db_session, server_args, miner_hotkey)
    mock_db_session.commit.assert_called()

    # Step 2: Check ownership
    mock_ownership_result = Mock()
    mock_ownership_result.scalar_one_or_none.return_value = sample_server
    mock_db_session.execute.return_value = mock_ownership_result

    owned_server = await check_server_ownership(mock_db_session, "test-server-123", miner_hotkey)
    assert owned_server == sample_server

    # Step 3: Delete server
    sample_server.compute_type = "cpu"
    with patch("api.server.service.check_server_ownership", return_value=sample_server):
        mock_db_session.execute.return_value = _empty_server_retirement_result()
        deleted = await delete_server(mock_db_session, "test-server-123", miner_hotkey)
        assert deleted is True


# Error Recovery Tests


@pytest.mark.asyncio
async def test_boot_attestation_partial_failure_recovery(
    mock_db_session,
    boot_attestation_args,
    boot_nonce_context,
    sample_boot_quote,
    sample_server,
):
    """Test boot attestation handles partial failures gracefully."""
    mock_db_session.get.return_value = sample_server
    # Simulate verification failure but ensure failed record is still created
    with patch("api.server.service.BootTdxQuote.from_base64", return_value=sample_boot_quote):
        with patch(
            "api.server.service.verify_quote",
            side_effect=MeasurementMismatchError("MRTD mismatch"),
        ):
            with pytest.raises(MeasurementMismatchError):
                await process_boot_attestation(
                    mock_db_session,
                    TEST_SERVER_IP,
                    boot_attestation_args,
                    TEST_NONCE,
                    boot_nonce_context,
                    TEST_CERT_HASH,
                )

            # Should still create failed attestation record
            mock_db_session.add.assert_called_once()
            mock_db_session.commit.assert_called_once()

            # Verify the failed record has correct fields
            call_args = mock_db_session.add.call_args[0][0]
            assert isinstance(call_args, BootAttestation)
            assert call_args.verification_error == "MRTD mismatch"


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "verification_error",
    [
        InvalidQuoteError("Invalid quote"),
        InvalidSignatureError("Invalid signature"),
    ],
)
async def test_runtime_attestation_partial_failure_recovery(
    mock_db_session,
    runtime_attestation_args,
    sample_runtime_quote,
    sample_server,
    runtime_nonce_context,
    verification_error,
):
    """Test runtime attestation handles partial failures gracefully."""
    server_id = "test-server-123"
    miner_hotkey = "5FTestHotkey123"
    mock_db_session.execute.return_value = _latest_added_attempt_result(mock_db_session)

    with patch("api.server.service.check_server_ownership", return_value=sample_server):
        with patch("api.server.service.build_runtime_quote", return_value=sample_runtime_quote):
            with patch(
                "api.server.service.verify_quote",
                side_effect=verification_error,
            ):
                with pytest.raises(type(verification_error)):
                    await process_runtime_attestation(
                        mock_db_session,
                        server_id,
                        TEST_SERVER_IP,
                        runtime_attestation_args,
                        miner_hotkey,
                        TEST_NONCE,
                        TEST_CERT_HASH,
                        runtime_nonce_context,
                    )

                # Should still create failed attestation record
                mock_db_session.add.assert_called_once()
                assert mock_db_session.commit.await_count == 3
                mock_db_session.rollback.assert_awaited_once()
                assert mock_db_session.execute.await_count == 4

                # Verify the failed record has correct fields
                call_args = mock_db_session.add.call_args[0][0]
                assert isinstance(call_args, ServerAttestation)
                assert call_args.verification_error == verification_error.detail


# Performance and Concurrency Tests


@pytest.mark.asyncio
async def test_multiple_nonce_operations_concurrent(mock_settings):
    """Test concurrent nonce operations don't interfere."""
    # Override the generate_nonce mock to return unique values for each call
    with patch("api.server.service.generate_nonce", side_effect=lambda: secrets.token_hex(16)):
        # Create multiple nonces concurrently
        import asyncio

        tasks = [create_nonce(TEST_SERVER_IP, NoncePurpose.BOOT) for _ in range(5)]
        results = await asyncio.gather(*tasks)

        # All should succeed
        assert len(results) == 5
        for result in results:
            assert "nonce" in result
            assert "expires_at" in result

        # Redis should have been called 5 times
        assert mock_settings.redis_client.setex.call_count == 5


# Quote Type Specific Tests


@pytest.mark.asyncio
async def test_verify_quote_boot_vs_runtime_different_settings(mock_settings):
    """Boot/runtime share RTMR0-2 and use zero versus measured RTMR3."""
    boot_quote = BootTdxQuote(
        version=4,
        att_key_type=2,
        tee_type=0x81,
        mrtd="a" * 96,
        rtmr0="b" * 96,
        rtmr1="c" * 96,
        rtmr2="d" * 96,
        rtmr3="0" * 96,
        report_data=None,
        user_data="test",
        platform_id="0" * 32,
        raw_quote_size=4096,
        parsed_at=datetime.now(timezone.utc).isoformat(),
        raw_bytes=b"boot",
    )

    runtime_quote = RuntimeTdxQuote(
        version=4,
        att_key_type=2,
        tee_type=0x81,
        mrtd="a" * 96,
        rtmr0="b" * 96,
        rtmr1="c" * 96,
        rtmr2="d" * 96,
        rtmr3="i" * 96,
        report_data=None,
        user_data="test",
        platform_id="0" * 32,
        raw_quote_size=4096,
        parsed_at=datetime.now(timezone.utc).isoformat(),
        raw_bytes=b"runtime",
    )

    mock_settings.tee_measurements = [
        TeeMeasurementConfig(
            version="1",
            mrtd="a" * 96,
            name="test",
            rtmr0="b" * 96,
            rtmr1="c" * 96,
            rtmr2="d" * 96,
            runtime_rtmr3="i" * 96,
            expected_gpus=[],
            gpu_count=0,
        ),
    ]

    # DCAP result must match each quote for verify_result(); return matching result per call
    boot_dcap_result = TdxVerificationResult(
        mrtd="a" * 96,
        rtmr0="b" * 96,
        rtmr1="c" * 96,
        rtmr2="d" * 96,
        rtmr3="0" * 96,
        user_data="test",
        parsed_at=datetime.now(timezone.utc),
        status="UpToDate",
        advisory_ids=[],
        td_attributes="0000001000000000",
    )
    runtime_dcap_result = TdxVerificationResult(
        mrtd="a" * 96,
        rtmr0="b" * 96,
        rtmr1="c" * 96,
        rtmr2="d" * 96,
        rtmr3="i" * 96,
        user_data="test",
        parsed_at=datetime.now(timezone.utc),
        status="UpToDate",
        advisory_ids=[],
        td_attributes="0000001000000000",
    )

    with patch("api.server.util.verify_quote_signature") as mock_sig:
        mock_sig.side_effect = [boot_dcap_result, runtime_dcap_result]
        await verify_quote(boot_quote, TEST_NONCE, TEST_CERT_HASH)
        await verify_quote(runtime_quote, TEST_NONCE, TEST_CERT_HASH)

    assert mock_sig.call_count == 2


# Special Edge Cases


@pytest.mark.asyncio
async def test_get_server_attestation_status_failed_attestation(mock_db_session, sample_server):
    """Test getting server attestation status with failed attestation."""
    server_id = "test-server-123"
    miner_hotkey = "5FTestHotkey123"

    # Create failed attestation (verified inferred from verification_error is None)
    failed_attestation = ServerAttestation(
        attestation_id="failed-attest-123",
        server_id=server_id,
        quote_data=None,
        verification_error="Measurement mismatch",
        measurement_version=None,
        created_at=datetime.now(timezone.utc),
        verified_at=None,
    )

    with patch("api.server.service.check_server_ownership", return_value=sample_server):
        mock_result = Mock()
        mock_result.scalar_one_or_none.return_value = failed_attestation
        mock_db_session.execute.return_value = mock_result

        result = await get_server_attestation_status(mock_db_session, server_id, miner_hotkey)

        assert result["attestation_status"] == "failed"
        assert result["last_attestation"]["verified"] is False
        assert result["last_attestation"]["verification_error"] == "Measurement mismatch"
        assert result["last_attestation"]["verified_at"] is None


# Database Transaction Tests


@pytest.mark.asyncio
async def test_boot_attestation_database_rollback_on_error(
    mock_db_session,
    boot_attestation_args,
    boot_nonce_context,
    sample_boot_quote,
    sample_server,
):
    """Test that database operations are rolled back on errors."""
    mock_db_session.get.return_value = sample_server
    with patch("api.server.service.BootTdxQuote.from_base64", return_value=sample_boot_quote):
        with patch("api.server.service.verify_quote") as mock_verify:
            mock_verify.return_value = TdxVerificationResult(
                mrtd="a" * 96,
                rtmr0="b" * 96,
                rtmr1="c" * 96,
                rtmr2="d" * 96,
                rtmr3="e" * 96,
                user_data="test",
                parsed_at=datetime.now(timezone.utc),
                status="UpToDate",
                advisory_ids=[],
                td_attributes="0000001000000000",
            )

            # Mock commit to fail after add
            mock_db_session.commit.side_effect = Exception("Database connection lost")

            with pytest.raises(Exception, match="Database connection lost"):
                await process_boot_attestation(
                    mock_db_session,
                    TEST_SERVER_IP,
                    boot_attestation_args,
                    TEST_NONCE,
                    boot_nonce_context,
                    TEST_CERT_HASH,
                )

            # Verify add was called but rollback should not be called
            # (since we're not explicitly handling this exception)
            mock_db_session.add.assert_called_once()
            mock_db_session.commit.assert_called_once()


@pytest.mark.asyncio
async def test_runtime_attestation_database_rollback_on_error(
    mock_db_session,
    runtime_attestation_args,
    sample_runtime_quote,
    sample_server,
    runtime_nonce_context,
):
    """Test that runtime attestation database operations handle errors."""
    server_id = "test-server-123"
    miner_hotkey = "5FTestHotkey123"
    mock_db_session.execute.return_value = _latest_added_attempt_result(mock_db_session)

    with patch("api.server.service.check_server_ownership", return_value=sample_server):
        with patch("api.server.service.build_runtime_quote", return_value=sample_runtime_quote):
            with patch("api.server.service.verify_quote") as mock_verify:
                mock_verify.return_value = TdxVerificationResult(
                    mrtd="a" * 96,
                    rtmr0="d" * 96,
                    rtmr1="e" * 96,
                    rtmr2="f" * 96,
                    rtmr3="0" * 96,
                    user_data="test",
                    parsed_at=datetime.now(timezone.utc),
                    status="UpToDate",
                    advisory_ids=[],
                    td_attributes="0000001000000000",
                )

                # Mock refresh to fail
                mock_db_session.refresh.side_effect = Exception("Database error during refresh")

                with pytest.raises(Exception, match="Database error during refresh"):
                    await process_runtime_attestation(
                        mock_db_session,
                        server_id,
                        TEST_SERVER_IP,
                        runtime_attestation_args,
                        miner_hotkey,
                        TEST_NONCE,
                        TEST_CERT_HASH,
                        runtime_nonce_context,
                    )

                mock_db_session.add.assert_called_once()
                assert mock_db_session.commit.await_count == 3
                mock_db_session.rollback.assert_not_awaited()
                assert mock_db_session.execute.await_count == 4


# Comprehensive Quote Validation Tests


@pytest.mark.asyncio
async def test_verify_quote_with_different_quote_types(mock_verify_measurements):
    """Test quote verification with different quote implementations."""
    boot_result = TdxVerificationResult(
        mrtd="a" * 96,
        rtmr0="b" * 96,
        rtmr1="c" * 96,
        rtmr2="d" * 96,
        rtmr3="e" * 96,
        user_data="test",
        parsed_at=datetime.now(timezone.utc),
        status="UpToDate",
        advisory_ids=[],
        td_attributes="0000001000000000",
    )
    runtime_result = TdxVerificationResult(
        mrtd="a" * 96,
        rtmr0="d" * 96,
        rtmr1="e" * 96,
        rtmr2="f" * 96,
        rtmr3="0" * 96,
        user_data="test",
        parsed_at=datetime.now(timezone.utc),
        status="UpToDate",
        advisory_ids=[],
        td_attributes="0000001000000000",
    )

    # Test with BootTdxQuote
    boot_quote = BootTdxQuote(
        version=4,
        att_key_type=2,
        tee_type=0x81,
        mrtd="a" * 96,
        rtmr0="b" * 96,
        rtmr1="c" * 96,
        rtmr2="d" * 96,
        rtmr3="e" * 96,
        report_data=None,
        user_data="test",
        platform_id="0" * 32,
        raw_quote_size=4096,
        parsed_at=datetime.now(timezone.utc).isoformat(),
        raw_bytes=b"boot",
    )

    # Test with RuntimeTdxQuote
    runtime_quote = RuntimeTdxQuote(
        version=4,
        att_key_type=2,
        tee_type=0x81,
        mrtd="a" * 96,
        rtmr0="d" * 96,
        rtmr1="e" * 96,
        rtmr2="f" * 96,
        rtmr3="0" * 96,
        report_data=None,
        user_data="test",
        platform_id="0" * 32,
        raw_quote_size=4096,
        parsed_at=datetime.now(timezone.utc).isoformat(),
        raw_bytes=b"runtime",
    )

    with patch("api.server.util.verify_quote_signature") as mock_sig:
        mock_sig.side_effect = [boot_result, runtime_result]
        boot_verify_result = await verify_quote(boot_quote, TEST_NONCE, TEST_CERT_HASH)
        runtime_verify_result = await verify_quote(runtime_quote, TEST_NONCE, TEST_CERT_HASH)

    assert isinstance(boot_verify_result, TdxVerificationResult)
    assert isinstance(runtime_verify_result, TdxVerificationResult)
    assert mock_sig.call_count == 2
    assert mock_verify_measurements.call_count == 2


# CPU (GPU-less) server registration + verification tests


def _cpu_measurement_config():
    return TeeMeasurementConfig(
        version="1",
        mrtd="a" * 96,
        name="cpu-gcp",
        rtmr0="d" * 96,
        rtmr1="e" * 96,
        rtmr2="f" * 96,
        runtime_rtmr3="0" * 96,
        expected_gpus=[],
        gpu_count=0,
        provider="gcp",
    )


def _valid_cpu_benchmark(**overrides):
    benchmark = {
        "schema_version": 1,
        "cpu_cores": 8,
        "ram_gb": 32,
        "int_score": 1234.5,
        "float_score": 2345.6,
        "memory_bandwidth_mb_s": 15000.0,
        "hash_score": 999.9,
        "composite_score": 1500.0,
        "duration_ms": 4200,
    }
    benchmark.update(overrides)
    return benchmark


@pytest.fixture
def cpu_server_args():
    return ServerArgs(
        id="cpu-server-1",
        host="127.0.0.2",
        name="cpu-vm",
        compute_type="cpu",
        gpus=None,
    )


def test_server_args_cpu_allows_no_gpus():
    args = ServerArgs(id="s", host="1.2.3.4", compute_type="cpu")
    assert args.compute_type == "cpu"
    assert args.gpus is None


def test_server_args_gpu_requires_gpus():
    from pydantic import ValidationError

    with pytest.raises(ValidationError):
        ServerArgs(id="s", host="1.2.3.4")  # default compute_type gpu, no gpus


def test_server_args_invalid_compute_type():
    from pydantic import ValidationError

    with pytest.raises(ValidationError):
        ServerArgs(id="s", host="1.2.3.4", compute_type="tpu", gpus=None)


@pytest.mark.asyncio
async def test_register_server_cpu_skips_node_tracking(
    mock_db_session, cpu_server_args, sample_server
):
    """CPU servers must verify but never create GPU Node rows."""
    miner_hotkey = "5FTestHotkey123"

    with patch("api.server.service._track_server", return_value=sample_server):
        with patch("api.server.service._track_nodes", new_callable=AsyncMock) as mock_track_nodes:
            with patch(
                "api.server.service.verify_server",
                new_callable=AsyncMock,
                return_value="1",
            ) as mock_verify:
                await register_server(mock_db_session, cpu_server_args, miner_hotkey)

    mock_track_nodes.assert_not_called()
    mock_verify.assert_awaited_once()
    # verify_server is called with gpus=None for CPU servers.
    assert mock_verify.call_args.kwargs.get("gpus") is None
    assert sample_server.version == "1"


@pytest.mark.asyncio
async def test_verify_server_cpu_skips_gpu_evidence_and_persists_benchmark(
    mock_db_session, sample_server, sample_runtime_quote, mock_util_functions
):
    """CPU verify_server skips GPU evidence + GPU matching and persists CPU capacity."""
    benchmark = _valid_cpu_benchmark()
    cpu_cert = Mock()

    mock_client = Mock()
    mock_client.get_server_evidence = AsyncMock(
        return_value=(sample_runtime_quote, None, cpu_cert, benchmark)
    )

    with (
        patch("api.server.service.TeeServerClient", return_value=mock_client),
        patch(
            "api.server.service.get_matching_measurement_config",
            return_value=_cpu_measurement_config(),
        ),
        patch("api.server.service.get_public_key_hash", return_value=TEST_CERT_HASH),
        patch(
            "api.server.service.verify_quote",
            new_callable=AsyncMock,
            return_value=SimpleNamespace(revocation_status={}),
        ),
        patch("api.server.service.validate_gpus_for_measurements") as mock_validate_gpus,
    ):
        version = await verify_server(mock_db_session, sample_server, "5FTestHotkey123", gpus=None)

    assert version == "1"
    # GPU evidence + GPU matching must be skipped for CPU servers.
    mock_util_functions["mock_verify_gpu"].assert_not_called()
    mock_validate_gpus.assert_not_called()
    # CPU capacity + composite_score persisted on the server.
    assert sample_server.compute_type == "cpu"
    assert sample_server.cpu_cores == 8
    assert sample_server.ram_gb == 32
    assert sample_server.benchmark_score == 1500.0
    assert sample_server.benchmark == benchmark
    mock_db_session.add.assert_called_once()
    mock_db_session.commit.assert_called()


@pytest.mark.asyncio
async def test_verify_server_cpu_invalid_benchmark_raises(
    mock_db_session, sample_server, sample_runtime_quote, mock_util_functions
):
    """An invalid/missing CPU benchmark fails verification (validator never trusts the miner)."""
    from api.server.exceptions import InvalidCpuBenchmarkError

    bad_benchmark = _valid_cpu_benchmark()
    del bad_benchmark["composite_score"]
    cpu_cert = Mock()

    mock_client = Mock()
    mock_client.get_server_evidence = AsyncMock(
        return_value=(sample_runtime_quote, None, cpu_cert, bad_benchmark)
    )

    with (
        patch("api.server.service.TeeServerClient", return_value=mock_client),
        patch(
            "api.server.service.get_matching_measurement_config",
            return_value=_cpu_measurement_config(),
        ),
        patch("api.server.service.get_public_key_hash", return_value=TEST_CERT_HASH),
        patch(
            "api.server.service.verify_quote",
            new_callable=AsyncMock,
            return_value=SimpleNamespace(revocation_status={}),
        ),
    ):
        with pytest.raises(InvalidCpuBenchmarkError):
            await verify_server(mock_db_session, sample_server, "5FTestHotkey123", gpus=None)

    # A failed CPU attestation record is still persisted (finally block).
    mock_util_functions["mock_verify_gpu"].assert_not_called()
    mock_db_session.add.assert_called()
