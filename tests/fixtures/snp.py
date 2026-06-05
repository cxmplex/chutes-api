"""Test fixtures for AMD SEV-SNP attestation.

Backed by a REAL report + VCEK/ASK/ARK chain captured from an EPYC 9124 "Genoa" platform
(tests/assets/snp/), so the parser + verifier are exercised against genuine hardware output
rather than synthetic data. Mirrors tests/fixtures/tdx.py.
"""

import base64
from pathlib import Path

import pytest

SNP_ASSETS = Path("tests/assets/snp")

# Values present in tests/assets/snp/report.bin (the captured Genoa report).
EXPECTED_MEASUREMENT = (
    "2B47D8F297F8F27AD19F52E6A09481FBBC34C09A3E0F4FDD4295B49F9643022F8527655CDB32FC2D6CA03D97D0C6BCE0"
)
EXPECTED_REPORT_DATA = (
    "94B9A1462C8DEA6B404BE6D283BDBFFA4EFFF6C4FC6DAFE275E46466AC25FA2B"
    "FCF79FD71124101A421F8D71B82F48754A018BFD7E56F1007CDE7AD77B28C209"
)
EXPECTED_REPORTED_TCB = {"bootloader": 7, "tee": 0, "snp": 23, "microcode": 72}
EXPECTED_POLICY = 0x30000
PROCESSOR_MODEL = "Genoa"


@pytest.fixture
def snp_report_bytes() -> bytes:
    """Raw bytes of the real captured SNP attestation report (1184 bytes)."""
    p = SNP_ASSETS / "report.bin"
    if not p.exists():
        pytest.skip(f"SNP report fixture not found at {p}")
    return p.read_bytes()


@pytest.fixture
def snp_report_b64(snp_report_bytes) -> str:
    return base64.b64encode(snp_report_bytes).decode("utf-8")


@pytest.fixture
def gcp_snp_report_bytes() -> bytes:
    """Raw bytes of a real GCP N2D SEV-SNP report (Milan, version 5)."""
    p = SNP_ASSETS / "gcp-report.bin"
    if not p.exists():
        pytest.skip(f"GCP SNP report fixture not found at {p}")
    return p.read_bytes()


@pytest.fixture
def gcp_snp_cert_chain() -> bytes:
    """GCP SEV-SNP extended-report auxblob (GHCB cert table: VCEK + ASK + Milan ARK)."""
    p = SNP_ASSETS / "gcp-aux.bin"
    if not p.exists():
        pytest.skip(f"GCP SNP auxblob fixture not found at {p}")
    return p.read_bytes()


@pytest.fixture
def snp_certs() -> tuple[bytes, bytes, bytes, bytes]:
    """(vcek_der, ask_pem, ark_pem, ca_pem) captured from AMD KDS for offline chain verification."""
    return (
        (SNP_ASSETS / "vcek.der").read_bytes(),
        (SNP_ASSETS / "ask.pem").read_bytes(),
        (SNP_ASSETS / "ark.pem").read_bytes(),
        (SNP_ASSETS / "chain.pem").read_bytes(),
    )


def snp_measurement_config(
    *,
    measurement: str = EXPECTED_MEASUREMENT,
    policy: int = EXPECTED_POLICY,
    min_tcb: dict | None = None,
    processor_model: str = PROCESSOR_MODEL,
    version: str = "1.0.0-snp",
    name: str = "cpu-snp-genoa-4c",
):
    """Build a SEV-SNP TeeMeasurementConfig matching (by default) the captured report."""
    from api.config import TeeMeasurementConfig

    return TeeMeasurementConfig(
        version=version,
        mrtd="",
        name=name,
        boot_rtmrs={},
        runtime_rtmrs={},
        expected_gpus=[],
        gpu_count=0,
        tee_type="sev-snp",
        measurement=measurement,
        policy=policy,
        min_tcb=dict(min_tcb) if min_tcb is not None else dict(EXPECTED_REPORTED_TCB),
        processor_model=processor_model,
    )
