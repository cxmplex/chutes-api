"""AMD SEV-SNP parser/verifier tests using deterministic valid synthetic crypto fixtures."""

# Pytest fixture parameters intentionally reuse the imported fixture function names.
# ruff: noqa: F811

from unittest.mock import PropertyMock, patch

import pytest
from cryptography import x509

from api.config import Settings, TeeMeasurementConfig
from api.server import util
from api.server import snp_verify
from api.server.exceptions import InvalidQuoteError, MeasurementMismatchError
from api.server.quote import build_runtime_quote, quote_from_evidence
from api.server.snp_quote import SnpReport
from api.server.snp_verify import verify_snp_report
from tests.fixtures.snp import (
    EXPECTED_MEASUREMENT,
    EXPECTED_REPORT_DATA,
    EXPECTED_REPORTED_TCB,
    PROCESSOR_MODEL,
    gcp_snp_cert_chain,  # noqa: F401 (pytest fixture)
    gcp_snp_report_bytes,  # noqa: F401
    snp_certs,  # noqa: F401
    snp_measurement_config,
    snp_report_b64,  # noqa: F401
    snp_report_bytes,  # noqa: F401
)
from tests.fixtures.snp_synthetic import SYNTHETIC_SNP_BUNDLE


class _MemoryRedis:
    def __init__(self, values=None):
        self.values = dict(values or {})

    async def get(self, key):
        return self.values.get(key)

    async def set(self, key, value, **_kwargs):
        self.values[key] = value

    async def delete(self, key):
        self.values.pop(key, None)


def _synthetic_redis(report=None):
    ask = x509.load_pem_x509_certificate(SYNTHETIC_SNP_BUNDLE.ask_pem)
    crl = x509.load_der_x509_crl(SYNTHETIC_SNP_BUNDLE.crl_der)
    values = {
        f"snp:crl:{PROCESSOR_MODEL}": snp_verify._crl_cache_payload(
            SYNTHETIC_SNP_BUNDLE.crl_der, crl, ask
        )
    }
    if report is not None:
        values.update(
            {
                f"snp:vcek:{PROCESSOR_MODEL}:{report.chip_id.lower()}:{report.reported_tcb}": (
                    SYNTHETIC_SNP_BUNDLE.vcek_der
                ),
                f"snp:ca:{PROCESSOR_MODEL}": SYNTHETIC_SNP_BUNDLE.ca_pem,
            }
        )
    return _MemoryRedis(values)


@pytest.fixture(autouse=True)
def _trust_synthetic_ark(monkeypatch):
    monkeypatch.setitem(
        snp_verify.ARK_PUBKEY_SHA384,
        PROCESSOR_MODEL,
        SYNTHETIC_SNP_BUNDLE.ark_spki_sha384,
    )


# --------------------------------------------------------------------------------------------------
# Parser (api/server/snp_quote.py)
# --------------------------------------------------------------------------------------------------


def test_snp_parse_offsets(snp_report_bytes):
    r = SnpReport.from_bytes(snp_report_bytes)
    assert r.version == 3
    assert r.measurement == EXPECTED_MEASUREMENT
    assert r.report_data == EXPECTED_REPORT_DATA
    assert r.reported_tcb_parts == EXPECTED_REPORTED_TCB
    assert r.policy == 0x30000
    assert r.quote_type == "runtime"
    assert r.debug_enabled is False
    assert len(r.chip_id) == 128
    assert len(r.signature_r) == 72 and len(r.signature_s) == 72
    assert len(r.signed_data) == 0x2A0


def test_snp_report_data_split_matches_tdx(snp_report_bytes):
    """report_data[:64]/[64:128] split is identical to TDX so extract_report_data is unchanged."""
    r = SnpReport.from_bytes(snp_report_bytes)
    nonce, cert_hash = util.extract_report_data(r)
    assert nonce == EXPECTED_REPORT_DATA[:64].lower()
    assert cert_hash == EXPECTED_REPORT_DATA[64:128].lower()


def test_snp_from_base64(snp_report_b64):
    r = SnpReport.from_base64(snp_report_b64)
    assert r.measurement == EXPECTED_MEASUREMENT


def test_snp_parse_too_short_raises():
    with pytest.raises(InvalidQuoteError):
        SnpReport.from_bytes(b"\x03\x00\x00\x00" + b"\x00" * 100)


def test_snp_parse_bad_version_raises(snp_report_bytes):
    tampered = bytearray(snp_report_bytes)
    tampered[0] = 1  # version 1 (< the v2 minimum)
    with pytest.raises(InvalidQuoteError):
        SnpReport.from_bytes(bytes(tampered))


def test_snp_parse_accepts_v5(snp_report_bytes):
    """Newer report versions (e.g. v5 on GCP firmware) keep the field offsets and must parse."""
    b = bytearray(snp_report_bytes)
    b[0] = 5
    r = SnpReport.from_bytes(bytes(b))
    assert r.version == 5 and len(r.measurement) == 96


# --------------------------------------------------------------------------------------------------
# matches_measurement
# --------------------------------------------------------------------------------------------------


def test_snp_matches_measurement(snp_report_bytes):
    r = SnpReport.from_bytes(snp_report_bytes)
    assert r.matches_measurement(snp_measurement_config()) is True


def test_snp_matches_measurement_wrong_measurement(snp_report_bytes):
    r = SnpReport.from_bytes(snp_report_bytes)
    assert r.matches_measurement(snp_measurement_config(measurement="00" * 48)) is False


def test_snp_matches_measurement_tcb_rollback(snp_report_bytes):
    r = SnpReport.from_bytes(snp_report_bytes)
    cfg = snp_measurement_config(min_tcb={"bootloader": 7, "tee": 0, "snp": 99, "microcode": 72})
    assert r.matches_measurement(cfg) is False


def test_snp_matches_measurement_wrong_policy(snp_report_bytes):
    """The full guest policy is pinned: a non-DEBUG policy bit the launch measurement does not cover
    (e.g. MIGRATE_MA, bit 20) must still fail the match when the config pins a different policy."""
    r = SnpReport.from_bytes(snp_report_bytes)  # report policy == EXPECTED_POLICY (0x30000)
    cfg = snp_measurement_config(
        policy=0x30000 | (1 << 20)
    )  # not DEBUG (bit 19); differs from report
    assert r.matches_measurement(cfg) is False


def test_snp_does_not_match_tdx_config(snp_report_bytes):
    r = SnpReport.from_bytes(snp_report_bytes)
    tdx_cfg = TeeMeasurementConfig(
        version="1",
        mrtd="A" * 96,
        name="tdx",
        boot_rtmrs={f"RTMR{i}": "B" * 96 for i in range(4)},
        runtime_rtmrs={f"RTMR{i}": "B" * 96 for i in range(4)},
        expected_gpus=[],
        tee_type="tdx",
    )
    assert r.matches_measurement(tdx_cfg) is False


def test_snp_matches_measurement_debug_rejected(snp_report_bytes):
    """A debug-enabled guest (policy bit 19) must never match, even with the right measurement."""
    tampered = bytearray(snp_report_bytes)
    tampered[0x08] |= 0x08  # set DEBUG (bit 19): 0x30000 -> 0x80000 region; byte 1 bit3
    # Set bit 19 explicitly: byte at offset 0x08 + 2, bit 3.
    tampered[0x0A] |= 0x08
    r = SnpReport.from_bytes(bytes(tampered))
    assert r.debug_enabled is True
    assert r.matches_measurement(snp_measurement_config()) is False


# --------------------------------------------------------------------------------------------------
# Verifier (api/server/snp_verify.py) -- offline against the captured cert chain
# --------------------------------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_snp_verify_positive(snp_report_bytes, snp_certs):
    vcek_der, ask_pem, ark_pem, _ca = snp_certs
    r = SnpReport.from_bytes(snp_report_bytes)
    res = await verify_snp_report(
        r,
        model=PROCESSOR_MODEL,
        vcek_der=vcek_der,
        ask_pem=ask_pem,
        ark_pem=ark_pem,
        redis=_synthetic_redis(),
    )
    assert res.is_valid is True
    assert res.status == "VALID"
    assert res.reported_tcb == EXPECTED_REPORTED_TCB


@pytest.mark.asyncio
async def test_snp_verify_tampered_measurement_rejected(snp_report_bytes, snp_certs):
    vcek_der, ask_pem, ark_pem, _ca = snp_certs
    tampered = bytearray(snp_report_bytes)
    tampered[0x90] ^= 0xFF  # flip a measurement byte -> breaks the report signature
    r = SnpReport.from_bytes(bytes(tampered))
    res = await verify_snp_report(
        r,
        model=PROCESSOR_MODEL,
        vcek_der=vcek_der,
        ask_pem=ask_pem,
        ark_pem=ark_pem,
        redis=_synthetic_redis(),
    )
    assert res.is_valid is False


@pytest.mark.asyncio
async def test_snp_verify_wrong_ark_pin_rejected(snp_report_bytes, snp_certs):
    vcek_der, ask_pem, ark_pem, _ca = snp_certs
    r = SnpReport.from_bytes(snp_report_bytes)
    res = await verify_snp_report(
        r, model="Milan", vcek_der=vcek_der, ask_pem=ask_pem, ark_pem=ark_pem
    )
    assert res.is_valid is False  # no pinned ARK for Milan


@pytest.mark.asyncio
async def test_snp_verify_broken_chain_rejected(snp_report_bytes, snp_certs):
    vcek_der, ask_pem, ark_pem, _ca = snp_certs
    r = SnpReport.from_bytes(snp_report_bytes)
    # Swap ASK/ARK so the ARK pin (and chain) fails.
    res = await verify_snp_report(
        r,
        model=PROCESSOR_MODEL,
        vcek_der=vcek_der,
        ask_pem=ark_pem,
        ark_pem=ask_pem,
    )
    assert res.is_valid is False


# --------------------------------------------------------------------------------------------------
# Provider-aware dispatch: build_runtime_quote / quote_from_evidence / verify_quote
# --------------------------------------------------------------------------------------------------


def test_build_runtime_quote_snp(snp_report_b64):
    assert isinstance(build_runtime_quote(snp_report_b64, "sev-snp"), SnpReport)


def test_quote_from_evidence_snp(snp_report_b64):
    q = quote_from_evidence({"tee_type": "sev-snp", "snp_report": snp_report_b64})
    assert isinstance(q, SnpReport)


@pytest.mark.asyncio
async def test_synthetic_snp_verify_via_inline_cert_chain(gcp_snp_report_bytes, gcp_snp_cert_chain):
    """The synthetic GHCB auxblob drives the inline VCEK/ASK/ARK verification path."""
    from api.server.snp_verify import parse_ghcb_cert_table

    r = SnpReport.from_bytes(gcp_snp_report_bytes)
    assert r.version == 3
    vcek, ask, ark = parse_ghcb_cert_table(gcp_snp_cert_chain)
    assert "ARK-Synthetic" in ark.subject.rfc4514_string()
    assert "VCEK" in vcek.subject.rfc4514_string()
    res = await verify_snp_report(r, cert_chain=gcp_snp_cert_chain, redis=_synthetic_redis())
    assert res.is_valid is True
    # Tamper -> the VCEK signature no longer verifies.
    bad = bytearray(gcp_snp_report_bytes)
    bad[0x90] ^= 0xFF
    res2 = await verify_snp_report(
        SnpReport.from_bytes(bytes(bad)),
        cert_chain=gcp_snp_cert_chain,
        redis=_synthetic_redis(),
    )
    assert res2.is_valid is False


@pytest.mark.asyncio
async def test_synthetic_crypto_executes_vmpl_and_id_key_mismatch_checks(
    snp_report_bytes, snp_certs
):
    vcek_der, ask_pem, ark_pem, _ca = snp_certs
    report = SnpReport.from_bytes(snp_report_bytes)
    result = await verify_snp_report(
        report,
        model=PROCESSOR_MODEL,
        vcek_der=vcek_der,
        ask_pem=ask_pem,
        ark_pem=ark_pem,
        redis=_synthetic_redis(),
    )
    assert result.is_valid
    util.verify_snp_measurement_constraints(report, snp_measurement_config())
    with pytest.raises(MeasurementMismatchError, match="VMPL"):
        util.verify_snp_measurement_constraints(report, snp_measurement_config(expected_vmpl=1))
    with pytest.raises(MeasurementMismatchError, match="exact configured"):
        util.verify_snp_measurement_constraints(
            report, snp_measurement_config(id_key_digest="00" * 48)
        )


@pytest.mark.asyncio
async def test_verify_quote_snp_dispatch(snp_report_bytes, snp_certs):
    """verify_quote routes an SnpReport through the SNP verifier + config match (offline KDS)."""
    r = SnpReport.from_bytes(snp_report_bytes)
    nonce = EXPECTED_REPORT_DATA[:64].lower()
    cert_hash = EXPECTED_REPORT_DATA[64:128].lower()
    redis = _synthetic_redis(r)

    with patch.object(Settings, "redis_client", new_callable=PropertyMock, return_value=redis):
        with patch.object(
            Settings,
            "tee_measurements",
            new_callable=PropertyMock,
            return_value=[snp_measurement_config()],
        ):
            res = await util.verify_quote(r, nonce, cert_hash)
            assert res.is_valid is True

        # Wrong measurement config -> MeasurementMismatchError.
        with patch.object(
            Settings,
            "tee_measurements",
            new_callable=PropertyMock,
            return_value=[snp_measurement_config(measurement="00" * 48)],
        ):
            with pytest.raises(MeasurementMismatchError):
                await util.verify_quote(r, nonce, cert_hash)
