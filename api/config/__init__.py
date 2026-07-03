"""
Application-wide settings.
"""

import os
import hashlib
from pathlib import Path
import aioboto3
import json
import yaml
from dataclasses import dataclass
from api.safe_redis import SafeRedis
from functools import cached_property, lru_cache
import redis.asyncio as redis
from redis.retry import Retry
from redis.backoff import ConstantBackoff
from boto3.session import Config
from typing import Dict, List, Optional
from bittensor_wallet.keypair import Keypair
from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict
from contextlib import asynccontextmanager
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.fernet import Fernet
from loguru import logger
from api.semver_util import semcomp


@lru_cache(maxsize=1)
def load_launch_config_private_key():
    if (path := os.getenv("LAUNCH_CONFIG_PRIVATE_KEY_PATH")) is not None:
        with open(path, "rb") as infile:
            return infile.read()
    return None


@dataclass
class TeeMeasurementConfig:
    """Configuration for allowed measurements for a TEE VM.

    Two TEE providers are supported, discriminated by ``tee_type``:
      - ``tdx`` (default): Intel TDX -- pins ``mrtd`` + ``boot_rtmrs``/``runtime_rtmrs`` (RTMR0-3).
      - ``sev-snp``: AMD SEV-SNP -- pins a single launch ``measurement`` (48B/96 hex) plus the
        guest ``policy`` (DEBUG must be off) and a minimum reported TCB (anti-rollback); there is
        no MRTD/RTMR concept. ``processor_model`` selects the AMD KDS/ARK (Genoa/Milan/Turin) and
        ``id_key_digest`` optionally pins an owner id-block. mrtd/rtmrs are left empty for SNP.
    """

    version: str
    mrtd: str
    name: str
    boot_rtmrs: Dict[str, str]
    runtime_rtmrs: Dict[str, str]
    expected_gpus: List[str]
    gpu_count: Optional[int] = None
    # Optional infrastructure provider hint ("gcp" | "bare-metal"). Used for CPU (gpu_count==0)
    # measurement configs; None for legacy GPU configs that don't specify it.
    provider: Optional[str] = None
    # TEE provider discriminator: "tdx" (default) or "sev-snp".
    tee_type: str = "tdx"
    # --- AMD SEV-SNP fields (only set when tee_type == "sev-snp") ---
    measurement: Optional[str] = None  # 96 hex (48B SHA-384 launch digest)
    policy: Optional[int] = None  # guest policy bits (DEBUG bit must be off)
    min_tcb: Optional[Dict[str, int]] = None  # {bootloader,tee,snp,microcode} minimums
    id_key_digest: Optional[str] = None  # 96 hex; optional owner id-block pin
    processor_model: Optional[str] = None  # Genoa | Milan | Turin (selects KDS/ARK)
    # Optional pinned SNP report VMPL (privilege level the guest attests at). Platform-specific:
    # bare-metal guests here attest at VMPL 1, GCP at VMPL 0 -- so it is pinned per measurement config
    # rather than hard-coded. None = not enforced (verify still checks chain/signature/TCB/debug).
    expected_vmpl: Optional[int] = None
    # GCP-only image identity: pinned GCE vTPM PCR values {pcr_index(str): sha256 hex}. On GCP the
    # SNP launch measurement is Google firmware only (no RTMR3 analog), so image identity (our
    # dm-verity rootfs) is bound via the Google-managed vTPM measured boot -- PCR8 (grub cmdline w/
    # verity.roothash) + PCR9 (kernel/initrd). When set, registration requires a verified vTPM quote
    # whose PCRs equal these. Unset for bare-metal SNP (image identity is in the SNP measurement).
    vtpm_pcrs: Optional[Dict[str, str]] = None


class Settings(BaseSettings):
    model_config = SettingsConfigDict(arbitrary_types_allowed=True)
    _validator_keypair: Optional[Keypair] = None

    def model_post_init(self, __context) -> None:
        """Validate configuration after initialization."""
        # Eagerly validate TEE measurement configuration when any source (committed artifact or the
        # mounted ConfigMap) is present.
        if self._measurement_source_paths():
            _ = self.tee_measurements

        # SKIP_METAGRAPH_CHECK is a dev-only bypass (it auto-creates a metagraph row so an unregistered
        # hotkey can self-register a CPU server). It must never run in the production posture, which is
        # identified by the secure mTLS-client-verify default. Fail closed on the unsafe combination;
        # the full dev posture (REQUIRE_MTLS_CLIENT_VERIFY=false) is still allowed for local bring-up.
        if self.skip_metagraph_check and self.require_mtls_client_verify:
            if not self.allow_dev_attested_mtls:
                raise ValueError(
                    "SKIP_METAGRAPH_CHECK is a dev-only bypass and must not be enabled in a production "
                    "posture (REQUIRE_MTLS_CLIENT_VERIFY=true). Set SKIP_METAGRAPH_CHECK=false, run a "
                    "full dev validator (REQUIRE_MTLS_CLIENT_VERIFY=false), or set ALLOW_DEV_ATTESTED_MTLS=true "
                    "to intentionally run a dev box with the metagraph bypass AND real attestation mTLS."
                )
            logger.warning(
                "Dev-attested-mTLS posture: SKIP_METAGRAPH_CHECK=true + REQUIRE_MTLS_CLIENT_VERIFY=true "
                "(ALLOW_DEV_ATTESTED_MTLS=true) -- dev metagraph with a REAL verifying mTLS terminator. "
                "This must NEVER be used on a production validator."
            )
        # The inverse direction must also fail closed: REQUIRE_MTLS_CLIENT_VERIFY=false disables the
        # X-Client-Verify gate AND the CPU-TEE attested-cert binding on secret-returning endpoints,
        # so flipping it alone on an otherwise-production validator would silently drop the sole
        # Model-B secret guard. Only the full dev posture (SKIP_METAGRAPH_CHECK=true, the dev-only
        # marker) may run without mTLS client verification; a non-dev validator refuses to start.
        if not self.skip_metagraph_check and not self.require_mtls_client_verify:
            raise ValueError(
                "REQUIRE_MTLS_CLIENT_VERIFY=false is a dev-only posture (no mTLS terminator) and "
                "must not be set on a non-dev validator: it would disable the attested-client-cert "
                "binding that keeps CPU-TEE chute code/secrets from unattested callers. Set "
                "REQUIRE_MTLS_CLIENT_VERIFY=true, or run the full dev posture "
                "(SKIP_METAGRAPH_CHECK=true) for local bring-up."
            )

    @cached_property
    def validator_keypair(self) -> Optional[Keypair]:
        if not self._validator_keypair and os.getenv("VALIDATOR_SEED"):
            self._validator_keypair = Keypair.create_from_seed(os.environ["VALIDATOR_SEED"])
        return self._validator_keypair

    @cached_property
    def fernet_key(self) -> Optional[Fernet]:
        """Get validated Fernet cipher for cache passphrase encryption.

        Returns:
            Fernet cipher instance, or None if CACHE_PASSPHRASE_KEY not configured

        Raises:
            ValueError: If CACHE_PASSPHRASE_KEY is invalid format
        """
        key = os.getenv("CACHE_PASSPHRASE_KEY")
        if not key:
            return None

        # Fernet keys must be 32 url-safe base64-encoded bytes (44 characters)
        if len(key) != 44:
            raise ValueError(
                f"CACHE_PASSPHRASE_KEY must be 44 characters (32 bytes base64-encoded), got {len(key)} characters. "
                "Generate a valid key with: python -c 'from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())'"
            )

        try:
            return Fernet(key.encode())
        except Exception as e:
            raise ValueError(f"Invalid CACHE_PASSPHRASE_KEY format: {e}")

    sqlalchemy: str = os.getenv(
        "POSTGRESQL", "postgresql+asyncpg://user:password@127.0.0.1:5432/chutes"
    )
    postgres_ro: Optional[str] = os.getenv("POSTGRESQL_RO")

    # Invocations database.
    invocations_db_url: Optional[str] = os.getenv(
        "INVOCATIONS_DB_URL",
        os.getenv("POSTGRESQL", "postgresql+asyncpg://user:password@127.0.0.1:5432/chutes"),
    )

    # asyncpg sslmode for the postgres connections. Defaults to "require" (prod hosted
    # postgres); set DB_SSL=disable for a local postgres that has no TLS.
    db_ssl: str = os.getenv("DB_SSL", "require")

    aws_access_key_id: str = os.getenv("AWS_ACCESS_KEY_ID", "REPLACEME")
    aws_secret_access_key: str = os.getenv("AWS_SECRET_ACCESS_KEY", "REPLACEME")
    aws_endpoint_url: Optional[str] = os.getenv("AWS_ENDPOINT_URL", "http://minio:9000")
    aws_region: str = os.getenv("AWS_REGION", "local")
    storage_bucket: str = os.getenv("STORAGE_BUCKET", "chutes")

    @property
    def s3_session(self) -> aioboto3.Session:
        session = aioboto3.Session(
            aws_access_key_id=self.aws_access_key_id,
            aws_secret_access_key=self.aws_secret_access_key,
            region_name=self.aws_region,
        )
        return session

    @asynccontextmanager
    async def s3_client(self):
        session = self.s3_session
        async with session.client(
            "s3",
            endpoint_url=self.aws_endpoint_url,
            config=Config(signature_version="s3v4"),
        ) as client:
            yield client

    wallet_key: Optional[str] = os.getenv(
        "WALLET_KEY", "967fcf63799171672b6b66dfe30d8cd678c8bc6fb44806f0cdba3d873b3dd60b"
    )
    pg_encryption_key: Optional[str] = os.getenv("PG_ENCRYPTION_KEY", "secret")

    validator_ss58: Optional[str] = os.getenv("VALIDATOR_SS58")
    storage_bucket: str = os.getenv("STORAGE_BUCKET", "REPLACEME")

    # Base redis settings.
    redis_host: str = Field(
        default_factory=lambda: os.getenv("HOST_IP", "172.16.0.100"),
        validation_alias="PRIMARY_REDIS_HOST",
    )
    redis_port: int = Field(
        default=1600,
        validation_alias="PRIMARY_REDIS_PORT",
    )
    redis_password: str = str(os.getenv("REDIS_PASSWORD", "password"))
    redis_db: int = int(os.getenv("REDIS_DB", "0"))
    redis_max_connections: int = int(os.getenv("REDIS_MAX_CONNECTIONS", 512))
    redis_connect_timeout: float = float(os.getenv("REDIS_CONNECT_TIMEOUT", "1.5"))
    redis_socket_timeout: float = float(os.getenv("REDIS_SOCKET_TIMEOUT", "2.5"))
    redis_op_timeout: float = float(
        os.getenv("REDIS_OP_TIMEOUT", os.getenv("REDIS_SOCKET_TIMEOUT", "2.5"))
    )

    _redis_client: Optional[redis.Redis] = None
    _lite_redis_client: Optional[redis.Redis] = None
    _billing_redis_client: Optional[redis.Redis] = None
    _cm_redis_clients: Optional[list[redis.Redis]] = None
    cm_redis_shard_count: int = int(os.getenv("CM_REDIS_SHARD_COUNT", "6"))
    cm_redis_start_port: int = int(os.getenv("CM_REDIS_START_PORT", "1700"))
    cm_redis_socket_timeout: float = float(os.getenv("CM_REDIS_SOCKET_TIMEOUT", "30.0"))
    cm_redis_op_timeout: float = float(os.getenv("CM_REDIS_OP_TIMEOUT", "2.5"))

    @property
    def redis_url(self) -> str:
        return f"redis://:{self.redis_password}@{self.redis_host}:{self.redis_port}/{self.redis_db}"

    @property
    def redis_client(self) -> redis.Redis:
        if self._redis_client is None:
            self._redis_client = SafeRedis(
                host=self.redis_host,
                port=self.redis_port,
                db=self.redis_db,
                password=self.redis_password,
                socket_connect_timeout=self.redis_connect_timeout,
                socket_timeout=self.redis_socket_timeout,
                op_timeout=self.redis_op_timeout,
                max_connections=self.redis_max_connections,
                socket_keepalive=True,
                health_check_interval=30,
                retry_on_timeout=True,
                retry=Retry(ConstantBackoff(0.5), 2),
            )
        return self._redis_client

    @property
    def lite_redis_client(self) -> redis.Redis:
        if self._lite_redis_client is None:
            self._lite_redis_client = SafeRedis(
                host=self.redis_host,
                port=self.redis_port,
                db=self.redis_db + 1,
                password=self.redis_password,
                socket_connect_timeout=self.redis_connect_timeout,
                socket_timeout=self.redis_socket_timeout,
                op_timeout=self.redis_op_timeout,
                max_connections=self.redis_max_connections,
                socket_keepalive=True,
                health_check_interval=30,
                retry_on_timeout=True,
                retry=Retry(ConstantBackoff(0.5), 2),
            )
        return self._lite_redis_client

    @property
    def billing_redis_client(self) -> redis.Redis:
        if self._billing_redis_client is None:
            self._billing_redis_client = SafeRedis(
                host=self.redis_host,
                port=self.redis_port,
                db=self.redis_db + 2,
                password=self.redis_password,
                socket_connect_timeout=self.redis_connect_timeout,
                socket_timeout=self.redis_socket_timeout,
                op_timeout=self.redis_op_timeout,
                max_connections=self.redis_max_connections,
                socket_keepalive=True,
                health_check_interval=30,
                retry_on_timeout=True,
                retry=Retry(ConstantBackoff(0.5), 2),
            )
        return self._billing_redis_client

    @property
    def cm_redis_client(self) -> list[redis.Redis]:
        if self._cm_redis_clients is None:
            self._cm_redis_clients = [
                SafeRedis(
                    host=self.redis_host,
                    port=self.cm_redis_start_port + idx,
                    db=self.redis_db,
                    password=self.redis_password,
                    socket_connect_timeout=self.redis_connect_timeout,
                    socket_timeout=self.cm_redis_socket_timeout,
                    op_timeout=self.cm_redis_op_timeout,
                    max_connections=self.redis_max_connections,
                    socket_keepalive=True,
                    health_check_interval=30,
                    retry_on_timeout=True,
                    retry=Retry(ConstantBackoff(0.5), 2),
                )
                for idx in range(self.cm_redis_shard_count)
            ]
        return self._cm_redis_clients

    registry_host: str = os.getenv("REGISTRY_HOST", "registry:5000")
    registry_external_host: str = os.getenv("REGISTRY_EXTERNAL_HOST", "registry.chutes.ai")
    registry_password: str = os.getenv("REGISTRY_PASSWORD", "registrypassword")
    registry_insecure: bool = os.getenv("REGISTRY_INSECURE", "false").lower() == "true"
    build_timeout: int = int(os.getenv("BUILD_TIMEOUT", "7200"))
    push_timeout: int = int(os.getenv("PUSH_TIMEOUT", "7200"))
    scan_timeout: int = int(os.getenv("SCAN_TIMEOUT", "7200"))
    netuid: int = int(os.getenv("NETUID", "64"))
    subtensor: str = os.getenv("SUBTENSOR_ADDRESS", "wss://entrypoint-finney.opentensor.ai:443")
    mev_protection_enabled: bool = os.getenv("MEV_PROTECTION_ENABLED", "false").lower() == "true"
    payment_recovery_blocks: int = int(os.getenv("PAYMENT_RECOVERY_BLOCKS", "256"))
    device_info_challenge_count: int = int(os.getenv("DEVICE_INFO_CHALLENGE_COUNT", "20"))
    skip_gpu_verification: bool = os.getenv("SKIP_GPU_VERIFICATION", "false").lower() == "true"
    # Dev-only: bypass the requirement that a self-registering CPU server's miner hotkey already
    # exists on the metagraph. When set, a metagraph_nodes row is auto-created on registration to
    # satisfy the servers FK. NEVER enable in production.
    skip_metagraph_check: bool = os.getenv("SKIP_METAGRAPH_CHECK", "false").lower() == "true"
    # Opt-in for a dev box that runs the metagraph bypass (SKIP_METAGRAPH_CHECK=true) AND fronts a
    # REAL verifying mTLS terminator (REQUIRE_MTLS_CLIENT_VERIFY=true) -- i.e. dev metagraph with real
    # attestation mTLS, needed to exercise CPU-TEE secret delivery without a live chain. Never set in
    # production (production uses a real metagraph, so SKIP_METAGRAPH_CHECK is false there anyway).
    allow_dev_attested_mtls: bool = os.getenv("ALLOW_DEV_ATTESTED_MTLS", "false").lower() == "true"
    # Debug TEE guest images (debug_logging: chute output forwarded to the host-readable serial
    # console) produce a DISTINCT measurement, but a validator cannot otherwise tell a debug
    # measurement from a hardened one -- so a debug config shipped in a production ConfigMap would
    # let a miner boot the debug image, pass attestation, and stream user logs to the host. A
    # measurement config tagged `debug: true` is therefore REFUSED at load unless this dev-only
    # switch is set, so debug measurements cannot silently enter a production deployment.
    allow_debug_measurements: bool = (
        os.getenv("ALLOW_DEBUG_MEASUREMENTS", "false").lower() == "true"
    )
    graval_url: str = os.getenv("GRAVAL_URL", "https://graval.chutes.ai:11443")

    # mTLS client-cert trust posture. The X-Client-Cert header is only honored when the mTLS-
    # terminating proxy also sets X-Client-Verify=SUCCESS (proving the proxy verified the peer's
    # private-key possession and set the header itself; the proxy must strip any client-supplied
    # X-Client-* and the backend must not be directly reachable). It also gates the CPU-TEE attested-
    # cert binding on the secret-returning /tee endpoints. Operator-controlled (trusted); set to
    # false ONLY for a dev validator reached directly over plaintext with no mTLS terminator.
    require_mtls_client_verify: bool = (
        os.getenv("REQUIRE_MTLS_CLIENT_VERIFY", "true").lower() == "true"
    )

    # Database settings.
    db_pool_size: int = int(os.getenv("DB_POOL_SIZE", "16"))
    db_overflow: int = int(os.getenv("DB_OVERFLOW", "3"))

    # Debug logging.
    debug: bool = os.getenv("DEBUG", "false").lower() == "true"

    # IP hash check salt.
    ip_check_salt: str = os.getenv("IP_CHECK_SALT", "salt")

    # User JWT salt.
    user_jwt_salt: Optional[str] = os.getenv("USER_JWT_SALT", "replaceme")

    # Flag indicating that all accounts created are free.
    all_accounts_free: bool = os.getenv("ALL_ACCOUNTS_FREE", "false").lower() == "true"

    # Consecutive failure count that triggers instance deletion.
    consecutive_failure_limit: int = int(os.getenv("CONSECUTIVE_FAILURE_LIMIT", "7"))

    # Logos CDN hostname.
    logo_cdn: Optional[str] = os.getenv("LOGO_CDN", "https://logos.chutes.ai")

    # Base domain.
    base_domain: Optional[str] = os.getenv("BASE_DOMAIN", "chutes.ai")

    # Base URL a launched chute calls back to for verification (the launch-JWT "url" claim). Defaults
    # to the public https://api.{base_domain}. A dev validator that a chute reaches over plain HTTP at
    # a raw IP:port (no api.<domain> DNS) sets LAUNCH_CONFIG_BASE_URL to its own reachable base.
    launch_config_base_url: Optional[str] = os.getenv("LAUNCH_CONFIG_BASE_URL")

    # Launch config JWT signing key.
    launch_config_key: str = hashlib.sha256(
        os.getenv("LAUNCH_CONFIG_KEY", "launch-secret").encode()
    ).hexdigest()

    # New, asymmetric launch config keys.
    launch_config_private_key_bytes: Optional[bytes] = load_launch_config_private_key()

    @cached_property
    def launch_config_private_key(self) -> Optional[ec.EllipticCurvePrivateKey]:
        if hasattr(self, "_launch_config_private_key"):
            return self._launch_config_private_key
        if (key_bytes := load_launch_config_private_key()) is not None:
            self._launch_config_private_key = serialization.load_pem_private_key(key_bytes, None)
        return self._launch_config_private_key

    # Default quotas/discounts.
    default_quotas: dict = json.loads(os.getenv("DEFAULT_QUOTAS", '{"*": 0}'))
    default_discounts: dict = json.loads(os.getenv("DEFAULT_DISCOUNTS", '{"*": 0.0}'))
    default_job_quotas: dict = json.loads(os.getenv("DEFAULT_JOB_QUOTAS", '{"*": 0}'))

    # Reroll discount (i.e. duplicate prompts for re-roll in RP, or pass@k, etc.)
    reroll_multiplier: float = float(os.getenv("REROLL_MULTIPLIER", "0.1"))

    # Magic discount header: when a request includes this header with the correct value,
    # a discount is applied to both quota increment and paygo charges.
    magic_discount_header_key: Optional[str] = os.getenv("MAGIC_DISCOUNT_HEADER_KEY")
    magic_discount_header_val: Optional[str] = os.getenv("MAGIC_DISCOUNT_HEADER_VAL")
    magic_discount_amount: float = float(os.getenv("MAGIC_DISCOUNT_AMOUNT", "0.5"))

    # Chutes pinned version.
    chutes_version: str = os.getenv("CHUTES_VERSION", "0.4.46")

    # Auto stake amount when DCAing into alpha after receiving payments.
    autostake_amount: float = float(os.getenv("AUTOSTAKE_AMOUNT", "10.0"))

    # Cosign Settings
    cosign_password: Optional[str] = os.getenv("COSIGN_PASSWORD")
    cosign_key: Optional[Path] = Path(os.getenv("COSIGN_KEY")) if os.getenv("COSIGN_KEY") else None

    # hCaptcha
    hcaptcha_sitekey: Optional[str] = os.getenv("HCAPTCHA_SITEKEY")
    hcaptcha_secret: Optional[str] = os.getenv("HCAPTCHA_SECRET")

    # TDX Attestation settings - Measurement configuration loaded from ConfigMap
    tee_measurement_config_path: Path = Path("/etc/config/tee_measurements.yaml")
    # A versioned (git-tracked, shipped-in-image) measurements artifact loaded ALONGSIDE the mounted
    # ConfigMap. The mounted file is environment/hardware specific and (in dev) gitignored, which
    # left the ChuteFS storage-* measurements as live-only hand-appended state -- so a from-repo
    # rebuild had no storage measurements and storage registration failed (H9). Committing the
    # storage-role measurements here makes them reproducible; the mounted file still overrides by
    # name for env-specific values.
    tee_committed_measurement_config_path: Path = Path(__file__).resolve().parent / "tee_measurements.committed.yaml"

    def _measurement_source_paths(self) -> List[Path]:
        """Existing measurement sources, committed base first then the (overriding) mounted file."""
        return [
            p
            for p in (self.tee_committed_measurement_config_path, self.tee_measurement_config_path)
            if p and Path(p).exists()
        ]

    @property
    def tee_measurements(self) -> List[TeeMeasurementConfig]:
        """Load TEE measurement configurations from YAML file (mounted from ConfigMap).

        Re-reads the file on every access so that ConfigMap updates propagated
        by Kubernetes are picked up without restarting the pod.
        """
        return self._load_tee_measurements()

    def _load_tee_measurements(self) -> List[TeeMeasurementConfig]:
        """Parse and validate TEE measurement configurations.

        Merges the committed (versioned) artifact with the mounted ConfigMap: entries are keyed by
        ``name`` and a mounted-file entry overrides a committed one of the same name, so
        environment-specific values win while the committed storage-role measurements stay a
        reproducible baseline.
        """
        raw_by_name: Dict[str, dict] = {}
        ordered_names: List[str] = []
        for path in self._measurement_source_paths():
            try:
                with open(path) as f:
                    doc = yaml.safe_load(f) or {}
            except Exception as e:
                logger.error(f"Failed to load TEE measurement config {path}: {e}")
                continue
            for measurement_config in doc.get("measurements") or []:
                name = measurement_config.get("name", "unnamed")
                if name not in raw_by_name:
                    ordered_names.append(name)
                raw_by_name[name] = measurement_config

        measurements: List[TeeMeasurementConfig] = []
        for config_name in ordered_names:
            measurement_config = raw_by_name[config_name]
            version = measurement_config.get("version")
            if not version or not str(version).strip():
                error_msg = (
                    f"Missing or empty 'version' for measurement config '{config_name}'. "
                    "Each measurement configuration must have a version."
                )
                logger.error(error_msg)
                raise ValueError(error_msg)

            # A measurement for a debug guest image (e.g. debug_logging -> chute output on the
            # host-readable serial console) must never be accepted in production: tag it `debug: true`
            # and the loader refuses it unless ALLOW_DEBUG_MEASUREMENTS is explicitly set (dev only),
            # so a debug image cannot pass attestation as a production measurement.
            if bool(measurement_config.get("debug", False)) and not self.allow_debug_measurements:
                raise ValueError(
                    f"Measurement config '{config_name}' is tagged debug: true but "
                    "ALLOW_DEBUG_MEASUREMENTS is not set. Debug images forward user logs to the "
                    "host-readable serial console and must not be accepted in production. Remove the "
                    "config from the production ConfigMap, or set ALLOW_DEBUG_MEASUREMENTS=true for a "
                    "dev validator."
                )

            def _require_hex96(value: object, field: str) -> str:
                text = str(value if value is not None else "").upper().strip()
                if len(text) != 96 or any(c not in "0123456789ABCDEF" for c in text):
                    raise ValueError(
                        f"Invalid {field} for measurement config '{config_name}': "
                        f"expected 96 hex characters, got {len(text)}."
                    )
                return text

            # gpu_count is REQUIRED and must be explicit. 0 denotes a CPU-only (GPU-less)
            # measurement config (the validator verifies measurements only and skips GPU
            # evidence / GPU-count matching). An absent gpu_count must NOT silently become a
            # CPU config -- that would skip GPU evidence verification for a GPU image.
            gpu_count = measurement_config.get("gpu_count")
            if gpu_count is None:
                raise ValueError(
                    f"Missing 'gpu_count' for measurement config '{config_name}'. "
                    "All TEE measurement configs must specify gpu_count (use 0 for CPU-only configs)."
                )
            gpu_count = int(gpu_count)
            # Optional infrastructure provider hint ("gcp" | "bare-metal").
            provider = measurement_config.get("provider")
            if provider is not None:
                provider = str(provider).strip().lower() or None
            expected_gpus = [gpu.lower() for gpu in measurement_config.get("expected_gpus", [])]
            tee_type = (str(measurement_config.get("tee_type") or "tdx")).strip().lower()

            # --- AMD SEV-SNP: single launch measurement + policy + min-TCB; no MRTD/RTMRs ---
            if tee_type in ("sev-snp", "snp", "amd-snp"):
                measurement_hex = _require_hex96(measurement_config.get("measurement"), "measurement")
                # policy is REQUIRED, not optional: the SNP launch measurement does not cover the
                # policy field, so an unpinned policy lets a host flip non-DEBUG bits (SMT,
                # MIGRATE_MA, ...) that the measurement match would never catch.
                raw_policy = measurement_config.get("policy")
                if raw_policy is None:
                    raise ValueError(
                        f"Missing 'policy' for SNP measurement config '{config_name}'. SNP configs "
                        "must pin the full guest policy (the launch measurement does not cover it)."
                    )
                # Accept either an int or a hex string like "0x30000".
                policy = int(str(raw_policy), 0) if isinstance(raw_policy, str) else int(raw_policy)
                if policy & (1 << 19):
                    raise ValueError(
                        f"SNP measurement config '{config_name}' sets the guest policy DEBUG "
                        "bit (0x80000); a debuggable guest offers no confidentiality. Refusing."
                    )
                # min_tcb is REQUIRED, not optional: without a minimum reported TCB there is no
                # anti-rollback -- a host could run firmware with known-vulnerable SPL levels and
                # still match the config.
                raw_min_tcb = measurement_config.get("min_tcb")
                if not raw_min_tcb:
                    raise ValueError(
                        f"Missing 'min_tcb' for SNP measurement config '{config_name}'. SNP configs "
                        "must pin minimum TCB levels ({{bootloader,tee,snp,microcode}}) for "
                        "anti-rollback."
                    )
                min_tcb = {str(k).lower(): int(v) for k, v in dict(raw_min_tcb).items()}
                id_key_digest = measurement_config.get("id_key_digest")
                if id_key_digest:
                    id_key_digest = _require_hex96(id_key_digest, "id_key_digest")
                processor_model = (str(measurement_config.get("processor_model") or "Genoa")).strip()
                # GCP image identity: pinned GCE vTPM PCRs (sha256, 64 hex each). REQUIRED for
                # provider 'gcp': there the SNP launch measurement is Google firmware only, so a
                # config without vtpm_pcrs would match on firmware alone and never check WHICH
                # image is running.
                # Image identity on SNP is provider-specific and MUST fail closed. On GCP the SNP
                # launch measurement is ONLY Google firmware (identical for every GCP SNP VM), so
                # image identity hangs entirely on the GCE vTPM PCRs; on bare-metal the dm-verity
                # roothash is folded into the SNP launch measurement, so the measurement IS the image
                # identity. A missing/unknown provider previously defaulted vtpm_pcrs off, which would
                # register an attacker-controlled image on real GCP SNP -- so provider is REQUIRED.
                snp_provider = "bare-metal" if provider == "baremetal" else provider
                if snp_provider not in ("gcp", "bare-metal"):
                    raise ValueError(
                        f"SNP measurement config '{config_name}' must set provider to 'gcp' or "
                        f"'bare-metal' (got {provider!r}); image identity is verified differently per "
                        "provider, so an unset/unknown provider is rejected (fail closed)."
                    )
                provider = snp_provider
                raw_vtpm = measurement_config.get("vtpm_pcrs")
                vtpm_pcrs = None
                if raw_vtpm:
                    vtpm_pcrs = {}
                    for k, v in dict(raw_vtpm).items():
                        val = str(v).upper().strip()
                        if len(val) != 64 or any(c not in "0123456789ABCDEF" for c in val):
                            raise ValueError(
                                f"Invalid vtpm_pcrs[{k}] for SNP config '{config_name}': "
                                f"expected 64 hex chars (sha256), got {len(val)}."
                            )
                        vtpm_pcrs[str(k)] = val
                if provider == "gcp":
                    # GCP SNP: require the vTPM PCRs, and require PCR8 (grub cmdline carrying
                    # verity.roothash) AND PCR9 (kernel/initrd) specifically. Without these exact two,
                    # the image is unpinned even if other (image-invariant) PCR indices are listed --
                    # so accepting "some PCRs" would not actually constrain WHICH image runs.
                    missing_pcrs = [p for p in ("8", "9") if not (vtpm_pcrs or {}).get(p)]
                    if missing_pcrs:
                        raise ValueError(
                            f"GCP SNP measurement config '{config_name}' must pin vtpm_pcrs including "
                            f"PCR8 and PCR9 (missing {missing_pcrs}). On GCP the SNP measurement "
                            "attests only Google firmware, so image identity MUST be pinned via the "
                            "GCE vTPM PCR8 (grub cmdline w/ verity.roothash) + PCR9 (kernel/initrd)."
                        )
                raw_vmpl = measurement_config.get("expected_vmpl")
                expected_vmpl = int(raw_vmpl) if raw_vmpl is not None else None
                measurements.append(
                    TeeMeasurementConfig(
                        version=str(version).strip(),
                        mrtd="",
                        name=measurement_config["name"],
                        boot_rtmrs={},
                        runtime_rtmrs={},
                        expected_gpus=expected_gpus,
                        gpu_count=gpu_count,
                        provider=provider,
                        tee_type="sev-snp",
                        measurement=measurement_hex,
                        policy=policy,
                        min_tcb=min_tcb,
                        id_key_digest=id_key_digest or None,
                        processor_model=processor_model,
                        expected_vmpl=expected_vmpl,
                        vtpm_pcrs=vtpm_pcrs,
                    )
                )
                continue

            # --- Intel TDX (default): MRTD + RTMR0-3 in both boot and runtime sets ---
            mrtd_upper = _require_hex96(measurement_config.get("mrtd"), "MRTD")

            # Every config MUST fully pin all four RTMRs in BOTH the boot and runtime
            # sets. The matcher only compares the RTMRs that are present in the config,
            # so a partially-specified config silently leaves the unlisted RTMRs
            # unconstrained -- a measurement-bypass footgun (e.g. omitting RTMR3 would
            # drop all runtime guest-stack enforcement). Reject it at load time.
            #
            # RTMR1/RTMR2 are LOAD-BEARING for the CPU-TEE integrity story, not optional
            # hardening: /boot (kernel, initramfs, grub.cfg) lives OUTSIDE the dm-verity
            # root, and the verity-roothash -> RTMR3 binding is performed by the initramfs
            # rtmr3-measure/verity-open scripts measured into RTMR1 (initramfs+kernel) with
            # the cmdline/grub.cfg in RTMR2. Without those pins a host could boot a tampered
            # initramfs that extends RTMR3 with the expected value WITHOUT opening the
            # verified root, voiding the agent/cosign integrity chain.
            if not isinstance(measurement_config.get("boot_rtmrs"), dict) or not isinstance(
                measurement_config.get("runtime_rtmrs"), dict
            ):
                raise ValueError(
                    f"Measurement config '{config_name}' must define both 'boot_rtmrs' and "
                    "'runtime_rtmrs' mappings."
                )
            boot_rtmrs = {
                k.upper(): _require_hex96(v, f"boot_rtmrs.{k}")
                for k, v in measurement_config["boot_rtmrs"].items()
            }
            runtime_rtmrs = {
                k.upper(): _require_hex96(v, f"runtime_rtmrs.{k}")
                for k, v in measurement_config["runtime_rtmrs"].items()
            }
            for set_name, rtmr_set in (("boot_rtmrs", boot_rtmrs), ("runtime_rtmrs", runtime_rtmrs)):
                missing = [r for r in ("RTMR0", "RTMR1", "RTMR2", "RTMR3") if r not in rtmr_set]
                if missing:
                    raise ValueError(
                        f"Measurement config '{config_name}' is missing {', '.join(missing)} in "
                        f"{set_name}; every config must pin RTMR0-3 in both the boot and runtime sets."
                    )

            if boot_rtmrs.get("RTMR0") != runtime_rtmrs.get("RTMR0"):
                logger.warning(
                    f"RTMR0 mismatch between boot and runtime for measurement config {config_name}. "
                    "This is unexpected - RTMR0 should be the same (ACPI tables don't change)."
                )

            measurements.append(
                TeeMeasurementConfig(
                    version=str(version).strip(),
                    mrtd=mrtd_upper,
                    name=measurement_config["name"],
                    boot_rtmrs=boot_rtmrs,
                    runtime_rtmrs=runtime_rtmrs,
                    expected_gpus=expected_gpus,
                    gpu_count=gpu_count,
                    provider=provider,
                    tee_type="tdx",
                )
            )

        logger.info(f"Loaded {len(measurements)} TEE measurement configurations")
        return measurements

    @property
    def tee_minimum_boot_version(self) -> str:
        """Minimum VM version accepted for boot attestation.

        Returns TEE_MINIMUM_BOOT_VERSION when set, allowing new platform measurement
        configs to be added to the YAML incrementally without immediately enforcing a
        version bump for platforms not yet upgraded.  Falls back to the highest version
        found across all loaded measurement configs, or "0.0.0" if the config file is
        not present (e.g. pods that don't mount the TEE measurements ConfigMap).
        """
        if pinned := os.getenv("TEE_MINIMUM_BOOT_VERSION"):
            return pinned
        if not self._measurement_source_paths():
            return "0.0.0"
        versions = [m.version for m in self.tee_measurements if m.version]
        if not versions:
            return "0.0.0"
        latest = versions[0]
        for v in versions[1:]:
            if semcomp(v, latest) > 0:
                latest = v
        return latest

    luks_passphrase: Optional[str] = os.getenv("LUKS_PASSPHRASE")
    cache_passphrase_key: Optional[str] = os.getenv("CACHE_PASSPHRASE_KEY")

    # TDX verification service URLs (if using Intel's remote verification)
    tdx_verification_url: Optional[str] = os.getenv("TDX_VERIFICATION_URL")
    tdx_cert_chain_url: Optional[str] = os.getenv("TDX_CERT_CHAIN_URL")

    # Nonce expiration (minutes)
    attestation_nonce_expiry: int = int(os.getenv("ATTESTATION_NONCE_EXPIRY", "10"))

    # OpenRouter free usage settings.
    or_free_user_id: str = os.getenv("OR_FREE_USER_ID", "replaceme")

    # Agent registration settings.
    agent_registration_threshold: float = float(os.getenv("AGENT_REGISTRATION_THRESHOLD", "50.0"))
    agent_registration_tolerance: float = float(os.getenv("AGENT_REGISTRATION_TOLERANCE", "0.10"))
    agent_registration_ttl_hours: int = int(os.getenv("AGENT_REGISTRATION_TTL_HOURS", "24"))


# Subscription tier: quota -> monthly price in USD (canonical values only).
SUBSCRIPTION_TIERS = {
    300: 3.0,
    2000: 10.0,
    5000: 20.0,
}
SUBSCRIPTION_PAYGO_DISCOUNTS = {
    3.0: 0.03,
    10.0: 0.06,
    20.0: 0.1,
}
SUBSCRIPTION_MONTHLY_CAP_MULTIPLIER = 5.0
SUBSCRIPTION_4H_CAP_MULTIPLIER = 75.0
FOUR_HOUR_CHUNKS_PER_MONTH = 180  # 30 days * 24 hours / 4 hours


def get_subscription_tier(quota: int) -> float | None:
    """
    Get the monthly price for a subscription quota value.
    Handles off-by-one quotas (e.g., 301, 2001, 5001) used for custom subs.
    """
    if quota in SUBSCRIPTION_TIERS:
        return SUBSCRIPTION_TIERS[quota]
    if quota - 1 in SUBSCRIPTION_TIERS:
        return SUBSCRIPTION_TIERS[quota - 1]
    return None


def is_custom_subscription(quota: int) -> bool:
    """Off-by-one quotas represent custom subscriptions."""
    return quota not in SUBSCRIPTION_TIERS and quota - 1 in SUBSCRIPTION_TIERS


settings = Settings()
