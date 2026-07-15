"""Pure-Python AMD SEV-SNP attestation verifier (the AMD analog of dcap-qvl for TDX).

No QGS/PCCS/QCNL and no new Rust dependency: SNP reports are signed by the per-chip VCEK, which
chains VCEK -> ASK -> ARK (AMD root). We fetch VCEK + the ASK/ARK CA chain from AMD's KDS
(kdsintf.amd.com), pin the ARK to an embedded AMD root public key, verify the certificate chain,
verify the report's ECDSA-P384 signature with the VCEK, bind the report's reported_tcb to the
VCEK's TCB extensions, and reject debug-enabled guests. Mirrors verify_quote_signature() in
api/server/util.py (which does the equivalent for TDX via dcap-qvl).

Verified end-to-end against a real EPYC 9124 "Genoa" report (tests/assets/snp/).
"""

import base64
import hashlib
import json
import struct
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature
from loguru import logger

from api.config import MAX_SNP_CRL_OUTAGE_GRACE_SECONDS
from api.server.cert_validity import check_cert_time_valid
from api.server.exceptions import InvalidQuoteError
from api.server.snp_quote import SnpReport

KDS_BASE = "https://kdsintf.amd.com"

# Pinned AMD Root Key (ARK) per processor model: SHA-384 of the ARK certificate's SubjectPublicKeyInfo
# (DER). The fetched ARK from KDS MUST hash to one of these -- this is the trust anchor (the AMD root),
# analogous to pinning Intel's root in the TDX path. Captured + verified from the live Genoa platform.
ARK_PUBKEY_SHA384 = {
    "Genoa": "32ab53a6ce5ec14926207396e5c475ae768a6a9831b7e860b5acf2e1c1dff222bc5a8bfc43eb5e06393189c1f246d880",
    # Milan captured from a GCP N2D SEV-SNP VM's inline cert chain (GCP signs with VCEK + provides
    # the full VCEK->ASK->ARK chain in the report's auxblob/GHCB cert table).
    "Milan": "1249f67f15cf229a4069195e1a9ce537d1765ef706a1f4a123c36be9518786515d25ecc007f366b564d2b3f31c48082e",
    # Turin ARK pin to be added when those platforms are onboarded.
}

# AMD VCEK certificate TCB extension OIDs (1.3.6.1.4.1.3704.1.3.x) -> reported_tcb component.
_VCEK_TCB_OID = {
    "1.3.6.1.4.1.3704.1.3.1": "bootloader",
    "1.3.6.1.4.1.3704.1.3.2": "tee",
    "1.3.6.1.4.1.3704.1.3.3": "snp",
    "1.3.6.1.4.1.3704.1.3.8": "microcode",
}
# HWID/product-name OID (value e.g. "Genoa").
_VCEK_HWID_OID = "1.3.6.1.4.1.3704.1.2"


@dataclass
class SnpVerificationResult:
    """Parsed/derived SNP verification outcome (the AMD analog of TdxVerificationResult)."""

    measurement: str
    reported_tcb: dict
    debug_enabled: bool
    chip_id: str
    status: str
    advisory_ids: list = field(default_factory=list)
    errors: list = field(default_factory=list)
    warnings: list = field(default_factory=list)
    revocation_status: dict = field(default_factory=dict)
    parsed_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    @property
    def is_valid(self) -> bool:
        """True only if every cryptographic check passed and the guest is not debug-enabled."""
        return self.status == "VALID" and not self.debug_enabled and not self.errors


def _spki_sha384(cert: x509.Certificate) -> str:
    spki = cert.public_key().public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return hashlib.sha384(spki).hexdigest()


def _verify_cert_signed_by(child: x509.Certificate, issuer_pubkey, what: str) -> None:
    """Verify `child`'s signature against `issuer_pubkey`. AMD ARK/ASK are RSA (PSS); VCEK is EC."""
    try:
        if isinstance(issuer_pubkey, ec.EllipticCurvePublicKey):
            issuer_pubkey.verify(
                child.signature,
                child.tbs_certificate_bytes,
                ec.ECDSA(child.signature_hash_algorithm),
            )
            return
        if isinstance(issuer_pubkey, rsa.RSAPublicKey):
            # Use the cert's own declared signature parameters (handles RSASSA-PSS, which AMD uses)
            # with a PSS fallback for older `cryptography`.
            try:
                issuer_pubkey.verify(
                    child.signature,
                    child.tbs_certificate_bytes,
                    child.signature_algorithm_parameters,
                    child.signature_hash_algorithm,
                )
                return
            except (TypeError, AttributeError):
                issuer_pubkey.verify(
                    child.signature,
                    child.tbs_certificate_bytes,
                    padding.PSS(
                        mgf=padding.MGF1(child.signature_hash_algorithm),
                        salt_length=padding.PSS.DIGEST_LENGTH,
                    ),
                    child.signature_hash_algorithm,
                )
                return
    except InvalidSignature:
        raise InvalidQuoteError(f"{what} signature is invalid (broken certificate chain)")
    raise InvalidQuoteError(f"unsupported issuer key type {type(issuer_pubkey).__name__}")


def _pin_ark(ark: x509.Certificate, model: Optional[str] = None) -> str:
    """Pin the ARK to a known AMD root by SHA-384 of its SubjectPublicKeyInfo.

    When ``model`` is given (KDS-fetch path) only that model's pin is accepted; otherwise (the
    inline-cert-chain path, e.g. GCP) the ARK may match any pinned model. Returns the matched model.
    """
    h = _spki_sha384(ark)
    if model is not None:
        pin = ARK_PUBKEY_SHA384.get(model)
        if not pin:
            raise InvalidQuoteError(f"no pinned ARK for SNP model {model!r}")
        if h != pin:
            raise InvalidQuoteError(
                "ARK public key does not match the pinned AMD root (untrusted root)"
            )
        return model
    for known_model, pin in ARK_PUBKEY_SHA384.items():
        if h == pin:
            return known_model
    raise InvalidQuoteError("ARK public key does not match any pinned AMD root (untrusted root)")


def _verify_chain(
    vcek: x509.Certificate,
    ask: x509.Certificate,
    ark: x509.Certificate,
    model: Optional[str] = None,
) -> str:
    """ARK pinned + self-signed; ASK signed by ARK; VCEK signed by ASK; all within their validity
    windows. Returns the matched model."""
    matched = _pin_ark(ark, model)
    check_cert_time_valid(ark, "ARK")
    check_cert_time_valid(ask, "ASK")
    check_cert_time_valid(vcek, "VCEK")
    _verify_cert_signed_by(ark, ark.public_key(), "ARK (self-signed)")
    _verify_cert_signed_by(ask, ark.public_key(), "ASK<-ARK")
    _verify_cert_signed_by(vcek, ask.public_key(), "VCEK<-ASK")
    return matched


def parse_ghcb_cert_table(
    aux: bytes,
) -> tuple[x509.Certificate, x509.Certificate, x509.Certificate]:
    """Parse the GHCB cert table (SNP extended-report auxblob) -> (vcek, ask, ark).

    Format: a sequence of entries {GUID(16) || offset(u32 LE) || length(u32 LE)} terminated by a
    zero entry, with DER certs at the given offsets. GCP SEV-SNP provides the full signing chain
    here. Certs are classified by subject CN (robust to GUID byte-order): ARK (root), the signing
    key (VCEK/VLEK), and the intermediate ASK.
    """
    certs: list[x509.Certificate] = []
    off = 0
    while off + 24 <= len(aux):
        guid = aux[off : off + 16]
        coff, clen = struct.unpack_from("<II", aux, off + 16)
        if guid == b"\x00" * 16 or (coff == 0 and clen == 0):
            break
        try:
            certificate = x509.load_der_x509_certificate(aux[coff : coff + clen])
        except ValueError:
            certificate = None
        if certificate is not None:
            certs.append(certificate)
        off += 24
    vcek = ask = ark = None
    for c in certs:
        cn = c.subject.rfc4514_string()
        if "ARK" in cn:
            ark = c
        elif "VCEK" in cn or "VLEK" in cn:
            vcek = c
        else:
            ask = c
    if not (vcek and ask and ark):
        raise InvalidQuoteError("auxblob GHCB cert table missing VCEK/ASK/ARK")
    return vcek, ask, ark


def _verify_report_signature(report: SnpReport, vcek: x509.Certificate) -> None:
    """Verify the report's ECDSA-P384 signature with the VCEK (R/S are 72B little-endian -> DER)."""
    pub = vcek.public_key()
    if not isinstance(pub, ec.EllipticCurvePublicKey):
        raise InvalidQuoteError("VCEK is not an EC key")
    r = int.from_bytes(report.signature_r, "little")
    s = int.from_bytes(report.signature_s, "little")
    try:
        pub.verify(encode_dss_signature(r, s), report.signed_data, ec.ECDSA(hashes.SHA384()))
    except InvalidSignature:
        raise InvalidQuoteError("VCEK did not sign this report (report signature invalid)")


def _vcek_tcb_parts(vcek: x509.Certificate) -> dict:
    parts: dict = {}
    for ext in vcek.extensions:
        comp = _VCEK_TCB_OID.get(ext.oid.dotted_string)
        if comp is None:
            continue
        raw = ext.value.value if hasattr(ext.value, "value") else bytes(ext.value.public_bytes())
        # Each TCB SPL extension is a small DER-encoded INTEGER/OCTET; take the last byte as the value.
        parts[comp] = raw[-1] if raw else 0
    return parts


def _check_tcb_binding(report: SnpReport, vcek: x509.Certificate) -> None:
    """The VCEK is issued for a specific TCB; require ALL FOUR SPL components to be present in the
    cert AND equal to the report's reported_tcb. Requiring presence (not merely iterating whatever
    parsed) prevents a vacuous pass if the VCEK TCB extensions fail to parse to an empty dict."""
    vcek_tcb = _vcek_tcb_parts(vcek)
    report_tcb = report.reported_tcb_parts
    expected_components = tuple(_VCEK_TCB_OID.values())  # bootloader, tee, snp, microcode
    missing = [comp for comp in expected_components if comp not in vcek_tcb]
    if missing:
        raise InvalidQuoteError(
            f"VCEK is missing TCB extension(s) {missing}; cannot bind the report's reported_tcb"
        )
    for comp in expected_components:
        if report_tcb.get(comp) != vcek_tcb.get(comp):
            raise InvalidQuoteError(
                f"reported_tcb {comp}={report_tcb.get(comp)} does not match VCEK cert "
                f"({vcek_tcb.get(comp)})"
            )


async def _kds_get(client, url: str) -> bytes:
    resp = await client.get(url, timeout=30.0)
    resp.raise_for_status()
    return resp.content


async def _fetch_vcek_and_ca(report: SnpReport, model: str, redis=None) -> tuple[bytes, bytes]:
    """Fetch the VCEK (DER, for the report's chip_id + reported_tcb) and the ASK+ARK cert_chain (PEM)
    from AMD KDS, caching both in Redis. report_data binding is unaffected (no nonce in the URL)."""
    import httpx

    tcb = report.reported_tcb_parts
    chip = report.chip_id.lower()
    vcek_url = (
        f"{KDS_BASE}/vcek/v1/{model}/{chip}"
        f"?blSPL={tcb['bootloader']:02}&teeSPL={tcb['tee']:02}"
        f"&snpSPL={tcb['snp']:02}&ucodeSPL={tcb['microcode']:02}"
    )
    ca_url = f"{KDS_BASE}/vcek/v1/{model}/cert_chain"
    vcek_key = f"snp:vcek:{model}:{chip}:{report.reported_tcb}"
    ca_key = f"snp:ca:{model}"

    if redis is not None:
        cached_vcek = await redis.get(vcek_key)
        cached_ca = await redis.get(ca_key)
        if cached_vcek and cached_ca:
            return cached_vcek, cached_ca

    async with httpx.AsyncClient() as client:
        vcek_der = await _kds_get(client, vcek_url)
        ca_pem = await _kds_get(client, ca_url)

    if redis is not None:
        # VCEK/CA rotate only on a TCB change; cache a day.
        await redis.set(vcek_key, vcek_der, ex=86400)
        await redis.set(ca_key, ca_pem, ex=86400)
    return vcek_der, ca_pem


def _load_ca_chain(ca_pem: bytes) -> tuple[x509.Certificate, x509.Certificate]:
    """KDS cert_chain is ASK then ARK (PEM). Return (ask, ark)."""
    certs = x509.load_pem_x509_certificates(ca_pem)
    ask = next((c for c in certs if "ARK" not in c.subject.rfc4514_string()), certs[0])
    ark = next((c for c in certs if "ARK" in c.subject.rfc4514_string()), certs[-1])
    return ask, ark


def _crl_times(crl: x509.CertificateRevocationList):
    try:
        return crl.last_update_utc, crl.next_update_utc
    except AttributeError:
        return (
            crl.last_update.replace(tzinfo=timezone.utc),
            crl.next_update.replace(tzinfo=timezone.utc) if crl.next_update is not None else None,
        )


def _check_crl_freshness(
    crl: x509.CertificateRevocationList, *, outage_grace_seconds: int = 0
) -> None:
    if (
        not isinstance(outage_grace_seconds, int)
        or isinstance(outage_grace_seconds, bool)
        or not 0 <= outage_grace_seconds <= MAX_SNP_CRL_OUTAGE_GRACE_SECONDS
    ):
        raise InvalidQuoteError("AMD VCEK CRL outage grace exceeds the enforced safe maximum")
    now = datetime.now(timezone.utc)
    last_update, next_update = _crl_times(crl)
    if last_update > now:
        raise InvalidQuoteError("AMD VCEK CRL is not yet valid")
    if next_update is None:
        raise InvalidQuoteError("AMD VCEK CRL has no nextUpdate freshness bound")
    if now > next_update and (now - next_update).total_seconds() > outage_grace_seconds:
        raise InvalidQuoteError("AMD VCEK CRL is expired")


async def _fetch_crl(model: str) -> bytes:
    """Fetch the AMD KDS VCEK CRL for a processor model without caching untrusted bytes."""
    import httpx

    async with httpx.AsyncClient() as client:
        return await _kds_get(client, f"{KDS_BASE}/vcek/v1/{model}/crl")


def _authenticated_crl(
    crl_der: bytes,
    ask: x509.Certificate,
    ark: x509.Certificate,
) -> x509.CertificateRevocationList:
    """Parse a CRL and require its named issuer and signature to match the pinned AMD chain."""
    try:
        crl = x509.load_der_x509_crl(crl_der)
    except ValueError as exc:
        raise InvalidQuoteError("AMD VCEK CRL is malformed") from exc
    possible_issuers = [
        issuer
        for issuer in (ark, ask)
        if crl.issuer == issuer.subject and crl.is_signature_valid(issuer.public_key())
    ]
    if not possible_issuers:
        raise InvalidQuoteError(
            "AMD VCEK CRL signature or issuer is invalid (not authenticated by the ARK/ASK)"
        )
    return crl


def _crl_signing_issuer(
    crl: x509.CertificateRevocationList,
    ask: x509.Certificate,
    ark: x509.Certificate,
) -> x509.Certificate:
    for issuer in (ark, ask):
        if crl.issuer == issuer.subject and crl.is_signature_valid(issuer.public_key()):
            return issuer
    raise InvalidQuoteError(
        "AMD VCEK CRL signature or issuer is invalid (not authenticated by the ARK/ASK)"
    )


def _crl_cache_payload(
    crl_der: bytes,
    crl: x509.CertificateRevocationList,
    issuer: x509.Certificate,
) -> str:
    last_update, next_update = _crl_times(crl)
    if next_update is None:
        raise InvalidQuoteError("AMD VCEK CRL has no nextUpdate freshness bound")
    return json.dumps(
        {
            "schema": 1,
            "der": base64.b64encode(crl_der).decode("ascii"),
            "sha256": hashlib.sha256(crl_der).hexdigest(),
            "issuer_spki_sha384": _spki_sha384(issuer),
            "last_update": last_update.isoformat(),
            "next_update": next_update.isoformat(),
        },
        sort_keys=True,
        separators=(",", ":"),
    )


def _load_cached_crl(
    payload: bytes | str,
    ask: x509.Certificate,
    ark: x509.Certificate,
) -> x509.CertificateRevocationList:
    try:
        if isinstance(payload, bytes):
            payload = payload.decode("ascii")
        document = json.loads(payload)
        expected_keys = {
            "schema",
            "der",
            "sha256",
            "issuer_spki_sha384",
            "last_update",
            "next_update",
        }
        if not isinstance(document, dict) or set(document) != expected_keys:
            raise ValueError("unexpected cache metadata")
        if document["schema"] != 1:
            raise ValueError("unsupported cache schema")
        crl_der = base64.b64decode(document["der"], validate=True)
        if hashlib.sha256(crl_der).hexdigest() != document["sha256"]:
            raise ValueError("CRL digest mismatch")
        crl = _authenticated_crl(crl_der, ask, ark)
        issuer = _crl_signing_issuer(crl, ask, ark)
        last_update, next_update = _crl_times(crl)
        if next_update is None:
            raise ValueError("missing nextUpdate")
        if (
            document["issuer_spki_sha384"] != _spki_sha384(issuer)
            or document["last_update"] != last_update.isoformat()
            or document["next_update"] != next_update.isoformat()
        ):
            raise ValueError("CRL cache metadata does not match signed content")
        return crl
    except (InvalidQuoteError, ValueError, TypeError, KeyError, UnicodeError) as exc:
        raise InvalidQuoteError("cached AMD VCEK CRL is unauthenticated or malformed") from exc


async def _cache_authenticated_crl(
    redis,
    cache_key: str,
    crl_der: bytes,
    crl: x509.CertificateRevocationList,
    issuer: x509.Certificate,
    *,
    outage_grace_seconds: int,
) -> None:
    _last_update, next_update = _crl_times(crl)
    if next_update is None:
        raise InvalidQuoteError("AMD VCEK CRL has no nextUpdate freshness bound")
    ttl = int((next_update - datetime.now(timezone.utc)).total_seconds() + outage_grace_seconds)
    if ttl <= 0:
        return
    await redis.set(
        cache_key,
        _crl_cache_payload(crl_der, crl, issuer),
        ex=ttl,
    )


def _reject_revoked_vcek(crl: x509.CertificateRevocationList, vcek: x509.Certificate) -> None:
    if crl.get_revoked_certificate_by_serial_number(vcek.serial_number) is not None:
        raise InvalidQuoteError("VCEK certificate is revoked (present in the AMD KDS CRL)")


async def _check_revocation(
    vcek: x509.Certificate,
    ask: x509.Certificate,
    ark: x509.Certificate,
    model: str,
    redis=None,
    *,
    outage_grace_seconds: int = 0,
) -> str:
    """Honor the AMD KDS CRL (M6): reject a VCEK whose serial is revoked.

    Fetches + caches the model's VCEK CRL and verifies its signature before honoring it (so a host
    can't feed a forged empty CRL). Per the AMD KDS spec (doc 57230) the VCEK CRL is issued + signed
    by the **ARK** (`CN=ARK-<product>`, RSASSA-PSS/sha384); we accept either the ARK or the ASK
    (both are already-verified AMD CA keys on the pinned chain) so revocation works regardless of
    which AMD CA signs a given product's CRL. Registration and key release fail closed when no
    authenticated CRL remains within its signed nextUpdate window.
    """
    if (
        not isinstance(outage_grace_seconds, int)
        or isinstance(outage_grace_seconds, bool)
        or not 0 <= outage_grace_seconds <= MAX_SNP_CRL_OUTAGE_GRACE_SECONDS
    ):
        raise InvalidQuoteError("AMD VCEK CRL outage grace exceeds the enforced safe maximum")
    cache_key = f"snp:crl:{model}"
    outage_candidate = None
    if redis is not None:
        cached_payload = await redis.get(cache_key)
        if cached_payload:
            try:
                cached_crl = _load_cached_crl(cached_payload, ask, ark)
            except InvalidQuoteError:
                await redis.delete(cache_key)
            else:
                try:
                    _check_crl_freshness(cached_crl)
                except InvalidQuoteError:
                    try:
                        _check_crl_freshness(
                            cached_crl,
                            outage_grace_seconds=outage_grace_seconds,
                        )
                    except InvalidQuoteError:
                        await redis.delete(cache_key)
                    else:
                        outage_candidate = cached_crl
                else:
                    _reject_revoked_vcek(cached_crl, vcek)
                    return "good"

    try:
        crl_der = await _fetch_crl(model)
        crl = _authenticated_crl(crl_der, ask, ark)
        _check_crl_freshness(crl)
        if redis is not None:
            issuer = _crl_signing_issuer(crl, ask, ark)
            await _cache_authenticated_crl(
                redis,
                cache_key,
                crl_der,
                crl,
                issuer,
                outage_grace_seconds=outage_grace_seconds,
            )
        _reject_revoked_vcek(crl, vcek)
        return "good"
    except InvalidQuoteError:
        # A malformed, future, expired, or incorrectly signed response from KDS is not an outage.
        # Never turn bad authenticated status into availability by falling back to stale state.
        raise
    except Exception as exc:
        if outage_candidate is not None:
            _reject_revoked_vcek(outage_candidate, vcek)
            logger.warning(
                "AMD KDS CRL fetch failed; using an authenticated CRL inside the configured "
                f"{outage_grace_seconds}s post-nextUpdate outage window: {exc}"
            )
            return "authenticated_outage_grace"
        raise InvalidQuoteError(
            f"AMD VCEK CRL is unavailable and no authenticated current cached "
            f"revocation state exists: {exc}"
        ) from exc


async def verify_snp_report(
    report: SnpReport,
    *,
    model: str = "Genoa",
    cert_chain: Optional[bytes] = None,
    vcek_der: Optional[bytes] = None,
    ask_pem: Optional[bytes] = None,
    ark_pem: Optional[bytes] = None,
    redis=None,
    crl_outage_grace_seconds: int = 0,
) -> SnpVerificationResult:
    """Verify an SNP report end-to-end.

    The VCEK->ASK->ARK chain is obtained from (in priority order): an inline ``cert_chain`` (the
    report's auxblob / GHCB cert table, as GCP SEV-SNP provides); explicit test certs
    (vcek_der/ask_pem/ark_pem); or an AMD KDS fetch keyed on the report's chip_id + reported_tcb
    (bare-metal). ``is_valid`` is True only when the ARK matches a pinned AMD root, the chain
    verifies, the VCEK signed the report (ECDSA-P384), reported_tcb matches the VCEK, and the guest
    is not debug-enabled.
    """
    result = SnpVerificationResult(
        measurement=report.measurement,
        reported_tcb=report.reported_tcb_parts,
        debug_enabled=report.debug_enabled,
        chip_id=report.chip_id,
        status="INVALID",
    )
    try:
        chain_model: Optional[str] = model
        if cert_chain is not None:
            # Inline chain (e.g. GCP auxblob): use the provided certs; pin ARK to any known model.
            vcek, ask, ark = parse_ghcb_cert_table(cert_chain)
            chain_model = None
        elif vcek_der is not None and ask_pem is not None and ark_pem is not None:
            vcek = x509.load_der_x509_certificate(vcek_der)
            ask = x509.load_pem_x509_certificate(ask_pem)
            ark = x509.load_pem_x509_certificate(ark_pem)
        else:
            vcek_der_b, ca_pem = await _fetch_vcek_and_ca(report, model, redis=redis)
            vcek = x509.load_der_x509_certificate(vcek_der_b)
            ask, ark = _load_ca_chain(ca_pem)

        matched_model = _verify_chain(vcek, ask, ark, chain_model)
        _verify_report_signature(report, vcek)
        _check_tcb_binding(report, vcek)
        revocation_status = await _check_revocation(
            vcek,
            ask,
            ark,
            matched_model,
            redis=redis,
            outage_grace_seconds=crl_outage_grace_seconds,
        )
        result.revocation_status["amd_vcek"] = revocation_status
        if revocation_status == "authenticated_outage_grace":
            result.warnings.append(
                "AMD VCEK revocation used an authenticated CRL inside the configured "
                "post-nextUpdate KDS outage window"
            )

        # L2: the report's VMPL is pinned at measurement-match time (config.expected_vmpl), not here.
        # Both current bare-metal and GCP fleets report VMPL 0; future platforms still need their
        # observed value pinned explicitly. This verifier stays pure crypto.
        if report.debug_enabled:
            result.errors.append("guest policy has DEBUG enabled (no confidentiality)")
        if not result.errors:
            result.status = "VALID"
            logger.success(
                f"SNP report verified: chip_id={report.chip_id[:16]}... "
                f"measurement={report.measurement[:16]}... tcb={report.reported_tcb_parts}"
            )
    except Exception as exc:  # noqa: BLE001 - any failure => not valid
        result.errors.append(str(exc))
        logger.error(f"SNP report verification failed: {exc}")
    return result
