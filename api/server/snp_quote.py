"""AMD SEV-SNP attestation report parser (ABI v2/v3, 1184 bytes).

The AMD analog of api/server/quote.py:TdxQuote. Deliberately mirrors that file's manual,
dependency-free byte parsing -- the field offsets below are confirmed against a real report
captured from an EPYC 9124 "Genoa" (tests/assets/snp/report.bin):

    version=3, policy=0x30000 (DEBUG off), reported_tcb bl=7/tee=0/snp=23/ucode=72,
    measurement=2b47d8f2..., report_data@0x50, host_data@0xC0, chip_id@0x1A0.

SnpReport exposes the TdxQuote-compatible surface the rest of the validator already uses:
``report_data`` (128-hex, so extract_report_data's [:64]/[64:128] split is unchanged),
``matches_measurement(config)``, ``quote_type``, and ``raw_bytes``. The cryptographic
verification (VCEK->ASK->ARK chain + ECDSA-P384 report signature) lives in snp_verify.py,
exactly as the TDX signature check lives in util.py (dcap-qvl), not here.
"""

import binascii
import struct
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Dict, Optional

import pybase64 as base64
from loguru import logger

from api.server.exceptions import InvalidQuoteError

# SNP attestation report ABI offsets (Genoa/Milan/Turin, report version 2 & 3).
SNP_REPORT_SIZE = 1184
_OFF_VERSION = 0x00  # u32
_OFF_POLICY = 0x08  # u64 (guest policy)
_OFF_VMPL = 0x30  # u32
_OFF_CURRENT_TCB = 0x38  # u64
_OFF_REPORT_DATA = 0x50  # 64 bytes
_OFF_MEASUREMENT = 0x90  # 48 bytes (SHA-384 launch digest)
_OFF_HOST_DATA = 0xC0  # 32 bytes (host-injected)
_OFF_ID_KEY_DIGEST = 0xE0  # 48 bytes
_OFF_AUTHOR_KEY_DIGEST = 0x110  # 48 bytes
_OFF_REPORTED_TCB = 0x180  # u64
_OFF_CHIP_ID = 0x1A0  # 64 bytes
_OFF_SIGNATURE = (
    0x2A0  # 512 bytes: R(72) || S(72) || reserved; ECDSA-P384, components little-endian
)

# The signature covers report bytes [0x00:0x2A0] (everything before the signature field).
_SIGNED_END = _OFF_SIGNATURE

# Guest policy DEBUG bit (AMD SEV-SNP ABI): when set the guest is debuggable -> no confidentiality.
_POLICY_DEBUG_BIT = 19


@dataclass
class SnpReport:
    """Parsed AMD SEV-SNP attestation report (the AMD analog of TdxQuote)."""

    version: int
    policy: int
    vmpl: int
    current_tcb: int
    reported_tcb: int
    report_data: (
        str  # 128 hex chars (64 bytes); split [:64]/[64:128] mirrors TDX (extract_report_data)
    )
    measurement: str  # 96 hex chars (48 bytes), uppercase
    host_data: str
    id_key_digest: str
    author_key_digest: str
    chip_id: str  # 128 hex chars (64 bytes)
    signature_r: bytes  # 72 raw bytes, little-endian
    signature_s: bytes  # 72 raw bytes, little-endian
    signed_data: bytes  # report[0x00:0x2A0] -- the bytes the signature covers
    raw_quote_size: int
    parsed_at: str
    raw_bytes: bytes
    # Optional inline VCEK->ASK->ARK chain (GHCB cert table / extended-report auxblob) supplied by
    # the hypervisor (SEV-SNP on GCP). When set, the verifier uses it instead of fetching from KDS.
    cert_chain: Optional[bytes] = None
    # Optional GCE vTPM measured-boot quote (GCP image identity): dict with base64 ak_cert/quote_msg/
    # quote_sig (+ optional intermediate) and a {pcr_index: hex} pcrs map. Verified by gcp_vtpm when
    # the matched SNP config pins vtpm_pcrs. None on bare-metal (image identity is in the measurement).
    vtpm_quote: Optional[Dict[str, Any]] = None

    @property
    def quote_type(self) -> str:
        """SNP has a single (runtime) report type; matched against runtime measurement config."""
        return "runtime"

    @property
    def debug_enabled(self) -> bool:
        """True if the guest policy permits debug (DEBUG bit set) -> reject (no confidentiality)."""
        return bool(self.policy & (1 << _POLICY_DEBUG_BIT))

    @property
    def reported_tcb_parts(self) -> Dict[str, int]:
        """Decompose reported_tcb into the SPL components used in the VCEK KDS URL.

        reported_tcb (u64, little-endian byte layout): byte0=bootloader, byte1=tee,
        byte6=snp, byte7=microcode. Confirmed: 0x4817000000000007 -> bl=7,tee=0,snp=23,ucode=72.
        """
        return {
            "bootloader": self.reported_tcb & 0xFF,
            "tee": (self.reported_tcb >> 8) & 0xFF,
            "snp": (self.reported_tcb >> 48) & 0xFF,
            "microcode": (self.reported_tcb >> 56) & 0xFF,
        }

    def matches_measurement(self, config) -> bool:
        """Return True if this SNP report matches the given SEV-SNP measurement config.

        For SNP (no MRTD/RTMRs) we compare the single launch ``measurement`` (case-insensitive),
        always require the guest policy DEBUG bit to be OFF, enforce a minimum reported TCB
        (anti-rollback), and optionally pin the owner ``id_key_digest`` (id-block launch binding).
        """
        # Only match SEV-SNP configs; TDX configs are matched by TdxQuote.matches_measurement.
        if getattr(config, "tee_type", "tdx") not in ("sev-snp", "snp", "amd-snp"):
            return False
        expected_measurement = getattr(config, "measurement", None)
        if not expected_measurement or self.measurement.upper() != expected_measurement.upper():
            return False
        # A debug-enabled guest offers no confidentiality -- never match.
        if self.debug_enabled:
            return False
        # Full guest-policy pin: the SNP launch measurement does NOT cover the policy field, so a host
        # could flip non-DEBUG policy bits (e.g. MIGRATE_MA, SMT) the measurement would not catch.
        # When the config pins a policy, require exact equality (DEBUG is also rejected above).
        expected_policy = getattr(config, "policy", None)
        if expected_policy is not None and self.policy != int(expected_policy):
            return False
        # Minimum-TCB (anti-rollback): each reported component must be >= the pinned minimum.
        min_tcb = getattr(config, "min_tcb", None)
        if min_tcb:
            parts = self.reported_tcb_parts
            for key, minimum in min_tcb.items():
                if minimum is not None and parts.get(key, 0) < int(minimum):
                    return False
        # Optional owner id-block binding: if the config pins an id_key_digest, it must match.
        expected_id_key = getattr(config, "id_key_digest", None)
        if expected_id_key and self.id_key_digest.upper() != expected_id_key.upper():
            return False
        return True

    @classmethod
    def from_base64(cls, report_base64: str) -> "SnpReport":
        try:
            return cls.from_bytes(base64.b64decode(report_base64))
        except binascii.Error:
            raise InvalidQuoteError("Invalid base64 SNP report.")

    @classmethod
    def from_bytes(cls, report_bytes: bytes) -> "SnpReport":
        """Parse a raw SNP attestation report. Raises InvalidQuoteError on any structural problem."""
        if len(report_bytes) < SNP_REPORT_SIZE:
            raise InvalidQuoteError(
                f"SNP report too short: {len(report_bytes)} bytes (need >= {SNP_REPORT_SIZE})"
            )
        try:
            version = struct.unpack_from("<I", report_bytes, _OFF_VERSION)[0]
            policy = struct.unpack_from("<Q", report_bytes, _OFF_POLICY)[0]
            vmpl = struct.unpack_from("<I", report_bytes, _OFF_VMPL)[0]
            current_tcb = struct.unpack_from("<Q", report_bytes, _OFF_CURRENT_TCB)[0]
            reported_tcb = struct.unpack_from("<Q", report_bytes, _OFF_REPORTED_TCB)[0]
        except struct.error as exc:
            raise InvalidQuoteError(f"Failed to parse SNP report header: {exc}")

        # v2 (original), v3 (cpuid fields), and newer (e.g. v5 on GCP firmware) keep the field
        # offsets below stable -- they only add fields in reserved space. Accept any >= 2.
        if version < 2:
            raise InvalidQuoteError(f"Unsupported SNP report version {version} (expected >= 2)")

        sig = report_bytes[_OFF_SIGNATURE : _OFF_SIGNATURE + 512]
        report = cls(
            version=version,
            policy=policy,
            vmpl=vmpl,
            current_tcb=current_tcb,
            reported_tcb=reported_tcb,
            report_data=report_bytes[_OFF_REPORT_DATA : _OFF_REPORT_DATA + 64].hex().upper(),
            measurement=report_bytes[_OFF_MEASUREMENT : _OFF_MEASUREMENT + 48].hex().upper(),
            host_data=report_bytes[_OFF_HOST_DATA : _OFF_HOST_DATA + 32].hex().upper(),
            id_key_digest=report_bytes[_OFF_ID_KEY_DIGEST : _OFF_ID_KEY_DIGEST + 48].hex().upper(),
            author_key_digest=report_bytes[_OFF_AUTHOR_KEY_DIGEST : _OFF_AUTHOR_KEY_DIGEST + 48]
            .hex()
            .upper(),
            chip_id=report_bytes[_OFF_CHIP_ID : _OFF_CHIP_ID + 64].hex().upper(),
            signature_r=sig[0:72],
            signature_s=sig[72:144],
            signed_data=report_bytes[0:_SIGNED_END],
            raw_quote_size=len(report_bytes),
            parsed_at=datetime.now(timezone.utc).isoformat(),
            raw_bytes=report_bytes,
        )
        logger.success(
            f"Parsed SNP report v{version}: measurement={report.measurement[:16]}... "
            f"chip_id={report.chip_id[:16]}... reported_tcb={report.reported_tcb_parts}"
        )
        return report

    def to_dict(self) -> Dict[str, Any]:
        return {
            "tee_type": "sev-snp",
            "version": self.version,
            "policy": hex(self.policy),
            "vmpl": self.vmpl,
            "measurement": self.measurement,
            "report_data": self.report_data,
            "host_data": self.host_data,
            "id_key_digest": self.id_key_digest,
            "reported_tcb": self.reported_tcb_parts,
            "chip_id": self.chip_id,
            "debug_enabled": self.debug_enabled,
            "raw_quote_size": self.raw_quote_size,
            "parsed_at": self.parsed_at,
        }
