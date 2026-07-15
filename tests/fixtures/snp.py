"""Mandatory deterministic synthetic AMD SEV-SNP attestation fixtures.

The report, VCEK/ASK/ARK chain, CRL, and GHCB cert table are cryptographically valid synthetic
test evidence. They are not real hardware output; hardware/provider validation remains live-only.
"""

import base64

import pytest

from tests.fixtures.snp_synthetic import (
    SYNTHETIC_ID_KEY_DIGEST,
    SYNTHETIC_MEASUREMENT,
    SYNTHETIC_MODEL,
    SYNTHETIC_POLICY,
    SYNTHETIC_REPORT_DATA,
    SYNTHETIC_SNP_BUNDLE,
    SYNTHETIC_TCB,
    SYNTHETIC_VMPL,
)

EXPECTED_MEASUREMENT = SYNTHETIC_MEASUREMENT
EXPECTED_REPORT_DATA = SYNTHETIC_REPORT_DATA
EXPECTED_REPORTED_TCB = SYNTHETIC_TCB
EXPECTED_POLICY = SYNTHETIC_POLICY
EXPECTED_VMPL = SYNTHETIC_VMPL
EXPECTED_ID_KEY_DIGEST = SYNTHETIC_ID_KEY_DIGEST
PROCESSOR_MODEL = SYNTHETIC_MODEL


@pytest.fixture
def snp_report_bytes() -> bytes:
    """Raw bytes of the valid synthetic SNP attestation report (1184 bytes)."""
    return SYNTHETIC_SNP_BUNDLE.report


@pytest.fixture
def snp_report_b64(snp_report_bytes) -> str:
    return base64.b64encode(snp_report_bytes).decode("utf-8")


@pytest.fixture
def gcp_snp_report_bytes() -> bytes:
    """Synthetic report used with the GHCB inline-chain fixture."""
    return SYNTHETIC_SNP_BUNDLE.report


@pytest.fixture
def gcp_snp_cert_chain() -> bytes:
    """Synthetic GHCB cert table containing VCEK + ASK + ARK."""
    return SYNTHETIC_SNP_BUNDLE.aux


@pytest.fixture
def snp_certs() -> tuple[bytes, bytes, bytes, bytes]:
    """Synthetic (vcek_der, ask_pem, ark_pem, ca_pem) for offline verification."""
    return (
        SYNTHETIC_SNP_BUNDLE.vcek_der,
        SYNTHETIC_SNP_BUNDLE.ask_pem,
        SYNTHETIC_SNP_BUNDLE.ark_pem,
        SYNTHETIC_SNP_BUNDLE.ca_pem,
    )


def snp_measurement_config(
    *,
    measurement: str = EXPECTED_MEASUREMENT,
    policy: int = EXPECTED_POLICY,
    min_tcb: dict | None = None,
    processor_model: str = PROCESSOR_MODEL,
    version: str = "1.0.0-snp",
    name: str = "cpu-snp-genoa-4c",
    expected_vmpl: int = EXPECTED_VMPL,
    id_key_digest: str | None = EXPECTED_ID_KEY_DIGEST,
):
    """Build a SEV-SNP TeeMeasurementConfig matching the synthetic report."""
    from api.config import TeeMeasurementConfig

    return TeeMeasurementConfig(
        version=version,
        mrtd="",
        name=name,
        boot_rtmrs={},
        runtime_rtmrs={},
        expected_gpus=[],
        gpu_count=0,
        provider="bare-metal",
        tee_type="sev-snp",
        measurement=measurement,
        policy=policy,
        min_tcb=dict(min_tcb) if min_tcb is not None else dict(EXPECTED_REPORTED_TCB),
        processor_model=processor_model,
        expected_vmpl=expected_vmpl,
        id_key_digest=id_key_digest,
    )
