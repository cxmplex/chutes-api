"""Verification for publisher-signed L0 bootstrap manifests."""

from __future__ import annotations

import base64
import json
import warnings
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, List, Literal

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from pydantic import BaseModel, ConfigDict, Field, field_validator

from api.releases.schemas import SignedL0BootstrapManifestV1

warnings.filterwarnings(
    "ignore",
    message=r'Field name "schema" in ".*" shadows an attribute in parent ".*"',
    category=UserWarning,
)

MAX_KEY_REGISTRY_BYTES = 64 * 1024
MAX_MANIFEST_LIFETIME = timedelta(days=7)
MAX_CLOCK_SKEW = timedelta(minutes=5)


class L0PublisherKeyV1(BaseModel):
    key_id: str = Field(..., min_length=1, max_length=128, pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]*$")
    epoch: int = Field(..., ge=1)
    public_key: str
    not_before: datetime
    not_after: datetime
    enabled: bool = True

    model_config = ConfigDict(extra="forbid", frozen=True)

    @field_validator("public_key")
    @classmethod
    def _valid_key(cls, value: str) -> str:
        try:
            decoded = base64.b64decode(value, validate=True)
        except (TypeError, ValueError) as exc:
            raise ValueError("public_key must be canonical base64") from exc
        if len(decoded) != 32 or base64.b64encode(decoded).decode("ascii") != value:
            raise ValueError("public_key must encode one canonical Ed25519 public key")
        return value


class L0PublisherKeyRegistryV1(BaseModel):
    schema: Literal["chutes.l0-publisher-keys"] = "chutes.l0-publisher-keys"
    version: Literal[1] = 1
    keys: List[L0PublisherKeyV1] = Field(..., min_length=1, max_length=32)

    model_config = ConfigDict(extra="forbid", frozen=True)


class L0BootstrapVerificationError(ValueError):
    """A manifest or publisher trust registry failed closed."""


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> Dict[str, Any]:
    result: Dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise L0BootstrapVerificationError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def load_l0_publisher_keys(path: Path) -> L0PublisherKeyRegistryV1:
    try:
        payload = path.read_bytes()
    except OSError as exc:
        raise L0BootstrapVerificationError(
            f"L0 publisher key registry is unavailable: {path}"
        ) from exc
    if not payload or len(payload) > MAX_KEY_REGISTRY_BYTES:
        raise L0BootstrapVerificationError("L0 publisher key registry has an invalid size")
    try:
        document = json.loads(
            payload.decode("utf-8"),
            object_pairs_hook=_reject_duplicate_keys,
            parse_constant=lambda value: (_ for _ in ()).throw(
                L0BootstrapVerificationError(f"invalid JSON constant: {value}")
            ),
        )
        registry = L0PublisherKeyRegistryV1.model_validate(document)
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
        if isinstance(exc, L0BootstrapVerificationError):
            raise
        raise L0BootstrapVerificationError(
            "L0 publisher key registry is not canonical schema v1 JSON"
        ) from exc
    identities = [(key.key_id, key.epoch) for key in registry.keys]
    if len(identities) != len(set(identities)):
        raise L0BootstrapVerificationError(
            "L0 publisher key registry contains duplicate key identities"
        )
    return registry


def verify_signed_l0_manifest(
    signed: SignedL0BootstrapManifestV1,
    keys_path: Path,
    *,
    now: datetime | None = None,
    allow_expired: bool = False,
) -> str:
    """Verify trust, time bounds, and detached signature; return canonical digest."""

    current = now or datetime.now(timezone.utc)
    if current.tzinfo is None:
        current = current.replace(tzinfo=timezone.utc)
    manifest = signed.manifest
    issued_at = manifest.issued_at
    expires_at = manifest.expires_at
    if issued_at.tzinfo is None:
        issued_at = issued_at.replace(tzinfo=timezone.utc)
    if expires_at.tzinfo is None:
        expires_at = expires_at.replace(tzinfo=timezone.utc)
    if issued_at > current + MAX_CLOCK_SKEW:
        raise L0BootstrapVerificationError("L0 manifest issue time is in the future")
    if expires_at <= current and not allow_expired:
        raise L0BootstrapVerificationError("L0 manifest has expired")
    if expires_at - issued_at > MAX_MANIFEST_LIFETIME:
        raise L0BootstrapVerificationError("L0 manifest lifetime exceeds seven days")

    registry = load_l0_publisher_keys(keys_path)
    matching = [
        key
        for key in registry.keys
        if key.key_id == manifest.key_id and key.epoch == manifest.key_epoch
    ]
    if len(matching) != 1:
        raise L0BootstrapVerificationError(
            "L0 manifest references an unknown publisher key identity"
        )
    key = matching[0]
    key_not_before = key.not_before
    key_not_after = key.not_after
    if key_not_before.tzinfo is None:
        key_not_before = key_not_before.replace(tzinfo=timezone.utc)
    if key_not_after.tzinfo is None:
        key_not_after = key_not_after.replace(tzinfo=timezone.utc)
    if not key.enabled or not (key_not_before <= issued_at < key_not_after):
        raise L0BootstrapVerificationError("L0 publisher key was not active at manifest issue time")
    try:
        public_key = Ed25519PublicKey.from_public_bytes(
            base64.b64decode(key.public_key, validate=True)
        )
        public_key.verify(
            base64.b64decode(signed.signature, validate=True),
            manifest.canonical_bytes(),
        )
    except (InvalidSignature, TypeError, ValueError) as exc:
        raise L0BootstrapVerificationError("L0 bootstrap manifest signature is invalid") from exc
    return manifest.digest()
