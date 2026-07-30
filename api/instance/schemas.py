"""
ORM definitions for instances (deployments of chutes and/or inventory announcements).
"""

import secrets
from loguru import logger
from pydantic import BaseModel, Field, constr
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.sql import func
from sqlalchemy.orm import relationship, deferred
from sqlalchemy import (
    Column,
    String,
    DateTime,
    Boolean,
    ForeignKey,
    Integer,
    Index,
    Table,
    Numeric,
    Double,
    UniqueConstraint,
    CheckConstraint,
    DDL,
    event,
    text,
)
from typing import Optional
from api.database import Base, generate_uuid
from api.metrics import launch_config as launch_config_metrics
from api.log import instance_logger, launch_config_logger, LifecycleEvent

# Association table.
instance_nodes = Table(
    "instance_nodes",
    Base.metadata,
    Column("instance_id", String, ForeignKey("instances.instance_id", ondelete="CASCADE")),
    Column("node_id", String, ForeignKey("nodes.uuid", ondelete="NO ACTION")),
    UniqueConstraint("instance_id", "node_id", name="uq_instance_node"),
    UniqueConstraint("node_id", name="uq_inode"),
)


class InstanceArgs(BaseModel):
    node_ids: list[str]
    host: str
    port: int


class ActivateArgs(BaseModel):
    active: bool


class PortMap(BaseModel):
    internal_port: int = Field(..., ge=22, le=65535)
    external_port: int = Field(..., ge=22, le=65535)
    proto: str = constr(pattern=r"^(tcp|udp|http)$")
    default: Optional[bool] = Field(default=None)


class LaunchConfigArgs(BaseModel):
    # Optional: CPU (GPU-less) chutes claim launch configs without GPU node info.
    gpus: Optional[list[dict]] = None
    host: str
    port_mappings: list[PortMap]
    fsv: Optional[str] = None
    egress: Optional[bool] = None
    lock_modules: Optional[bool] = None
    netnanny_hash: Optional[str] = None
    run_path: Optional[str] = None
    py_dirs: Optional[list[str]] = None
    rint_commitment: Optional[str] = None
    rint_nonce: Optional[str] = None
    rint_pubkey: Optional[str] = None
    tls_cert: Optional[str] = None
    tls_cert_sig: Optional[str] = None
    tls_ca_cert: Optional[str] = None
    tls_client_cert: Optional[str] = None
    tls_client_key: Optional[str] = None
    tls_client_key_password: Optional[str] = None
    e2e_pubkey: Optional[str] = None
    # CPU-TEE only: signature over f"{e2e_pubkey}:{config_id}" by the attested in-TD cert key, proving
    # the ML-KEM e2e key was generated inside the attested TD (GPU-TEE binds e2e_pubkey via the quote
    # report_data instead). Verified against the server's attested cert before the key is published.
    e2e_pubkey_sig: Optional[str] = None
    cllmv_session_init: Optional[str] = None
    # The aegis-backed envdump. CPU-TEE chutes ship no aegis and send no envdump; TD attestation
    # (dm-verity + RTMR) + cosign image verification anchor integrity instead.
    env: Optional[str] = None
    inspecto: Optional[str] = None


class LaunchRegistryScope(BaseModel):
    repository: str
    manifest_digest: str


class LaunchConfigResponse(BaseModel):
    token: str
    config_id: str
    registry: Optional[LaunchRegistryScope] = None


class TeeLaunchConfigArgs(LaunchConfigArgs):
    deployment_id: str


class LegacyTeeLaunchConfigArgs(LaunchConfigArgs):
    gpu_evidence: list[dict]


class Instance(Base):
    __tablename__ = "instances"
    instance_id = Column(String, primary_key=True, default=generate_uuid)
    host = Column(String, nullable=False)
    port = Column(Integer, nullable=False)
    chute_id = Column(String, ForeignKey("chutes.chute_id", ondelete="CASCADE"), nullable=False)
    version = Column(String, nullable=False)
    miner_uid = Column(Integer, nullable=False)
    miner_hotkey = Column(String, nullable=False)
    miner_coldkey = Column(String, nullable=False)
    region = Column(String)
    active = Column(Boolean, default=False)
    verified = Column(Boolean, default=False)
    last_queried_at = Column(DateTime(timezone=True))
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True))
    activated_at = Column(DateTime(timezone=True), nullable=True)
    last_verified_at = Column(DateTime(timezone=True))
    stop_billing_at = Column(DateTime, nullable=True)
    billed_to = Column(String, ForeignKey("users.user_id", ondelete="CASCADE"), nullable=True)
    verification_error = Column(String, nullable=True)
    consecutive_failures = Column(Integer, default=0)
    chutes_version = Column(String, nullable=True)
    symmetric_key = Column(String, default=lambda: secrets.token_bytes(16).hex())
    config_id = Column(
        String,
        ForeignKey("launch_configs.config_id", ondelete="SET NULL"),
        nullable=True,
        unique=True,
    )
    # Chute deployment ID; set when instance claims TEE launch config and is verified.
    deployment_id = Column(
        String,
        nullable=True,
    )
    # Explicit owning server for 1-click self-registered CPU servers (no GPU nodes to link
    # through, and no per-miner control plane). NULL for the legacy miner-run GPU/CPU path.
    server_id = Column(
        String,
        ForeignKey(
            "servers.server_id",
            name="fk_instances_server",
            ondelete="SET NULL",
        ),
        nullable=True,
    )
    gpu_management_mode = Column(String, nullable=True)
    gpu_launch_reservation_id = Column(
        String,
        ForeignKey(
            "gpu_launch_reservations.reservation_id",
            name="fk_instances_gpu_launch_reservation",
            ondelete="RESTRICT",
        ),
        nullable=True,
    )
    gpu_allocation_group_id = Column(
        String,
        ForeignKey(
            "gpu_allocation_groups.allocation_group_id",
            name="fk_instances_gpu_allocation_group",
            ondelete="RESTRICT",
        ),
        nullable=True,
    )
    gpu_allocation_group_generation = Column(Integer, nullable=True)
    gpu_process_incarnation = Column(String, nullable=True)
    cacert = Column(String, nullable=True)
    port_mappings = Column(JSONB, nullable=True)
    inspecto = Column(String, nullable=True)
    env_creation = deferred(Column(JSONB, nullable=True))
    bounty = Column(Boolean, default=False)

    # Runtime integrity (runint) commitment and nonce
    rint_commitment = Column(String, nullable=True)
    rint_nonce = Column(String, nullable=True)
    # ECDH session encryption: miner's pubkey and derived session key
    rint_pubkey = Column(String, nullable=True)
    rint_session_key = Column(String, nullable=True)

    # Flexible extra data (aegis v4 fields, future extensions)
    extra = Column(JSONB, nullable=True)

    # Hourly rate charged to customer, which may differ from the hourly rate of the actual
    # GPUs used for this instance due to node selector. For example, if a chute supports
    # both H100 and A100, the user is only charged the A100 rate since the miners *could*
    # have run it on A100s, regardless of whether or not they did so.
    hourly_rate = Column(Double, nullable=True)
    compute_multiplier = Column(Double, nullable=True)

    nodes = relationship("Node", secondary=instance_nodes, back_populates="instance")
    chute = relationship("Chute", back_populates="instances")
    job = relationship("Job", back_populates="instance", uselist=False)
    config = relationship("LaunchConfig", back_populates="instance", lazy="joined")
    billed_user = relationship("User", back_populates="instances")

    __table_args__ = (
        Index(
            "idx_chute_active_lastq",
            "chute_id",
            "active",
            "verified",
            "last_queried_at",
        ),
        UniqueConstraint("host", "port", name="unique_host_port"),
        Index(
            "uq_instances_gpu_reservation",
            "gpu_launch_reservation_id",
            unique=True,
            postgresql_where=text(
                "gpu_launch_reservation_id IS NOT NULL AND gpu_management_mode = 'platform'"
            ),
        ),
        CheckConstraint(
            "(gpu_management_mode IS NULL "
            "AND gpu_launch_reservation_id IS NULL "
            "AND gpu_allocation_group_id IS NULL "
            "AND gpu_allocation_group_generation IS NULL "
            "AND gpu_process_incarnation IS NULL) OR "
            "(gpu_management_mode IN ('platform', 'miner') "
            "AND gpu_launch_reservation_id IS NOT NULL "
            "AND gpu_allocation_group_id IS NOT NULL "
            "AND gpu_allocation_group_generation > 0 "
            "AND gpu_process_incarnation IS NOT NULL "
            "AND server_id IS NOT NULL)",
            name="ck_instances_gpu_manager",
        ),
    )


class LaunchConfig(Base):
    __tablename__ = "launch_configs"
    config_id = Column(String, primary_key=True, default=generate_uuid)
    seed = Column(Numeric, nullable=False)
    env_key = Column(String, nullable=False)
    chute_id = Column(String, ForeignKey("chutes.chute_id", ondelete="CASCADE"), nullable=False)
    # Authoritative storage owner. Jobs use Job.user_id; normal cord/deployment launches use
    # Chute.user_id. This must never be inferred from chute visibility at authorization time.
    user_id = Column(String, ForeignKey("users.user_id", ondelete="CASCADE"), nullable=False)
    compute_type = Column(String, nullable=False)
    default_volume_id = Column(
        String,
        ForeignKey("storage_volumes.volume_id", ondelete="RESTRICT"),
        nullable=True,
    )
    storage_session_exchange_allowed = Column(
        Boolean,
        nullable=False,
        default=False,
        server_default="false",
    )
    job_id = Column(
        String,
        ForeignKey("jobs.job_id", ondelete="CASCADE"),
        nullable=True,
    )
    host = Column(String, nullable=True)
    port = Column(Integer, nullable=True)
    env_type = Column(String, nullable=True)
    miner_uid = Column(Integer, nullable=False)
    miner_hotkey = Column(String, nullable=False)
    miner_coldkey = Column(String, nullable=False)
    # Durable idempotency identity for the miner-managed GPU launch response.  The
    # request UUID is generated and persisted by Gepetto before it contacts the
    # validator; the digest binds that UUID to the exact launch authority and JWT
    # policy accepted by the validator.
    miner_launch_request_id = Column(String(36), nullable=True)
    miner_launch_request_sha256 = Column(String(64), nullable=True)
    # Target self-registered server for 1-click CPU deployments (stamped by the scheduler);
    # propagated to the created Instance. NULL for the legacy miner-run path.
    server_id = Column(
        String,
        ForeignKey(
            "servers.server_id",
            name="fk_launch_configs_server",
            ondelete="RESTRICT",
        ),
        nullable=True,
    )
    gpu_management_mode = Column(String, nullable=True)
    gpu_launch_reservation_id = Column(
        String,
        ForeignKey(
            "gpu_launch_reservations.reservation_id",
            name="fk_launch_configs_gpu_launch_reservation",
            ondelete="RESTRICT",
        ),
        nullable=True,
    )
    container_repository = Column(String, nullable=True)
    container_manifest_digest = Column(String, nullable=True)
    registry_scope_active = Column(
        Boolean,
        nullable=False,
        default=False,
        server_default="false",
    )
    registry_scope_revoked_at = Column(DateTime(timezone=True), nullable=True)
    created_at = Column(DateTime, server_default=func.now())
    retrieved_at = Column(DateTime, nullable=True)
    verified_at = Column(DateTime, nullable=True)
    failed_at = Column(DateTime, nullable=True)
    completed_at = Column(DateTime(timezone=True), nullable=True)
    verification_error = Column(String, nullable=True)
    nonce = Column(String, nullable=True)

    instance = relationship("Instance", back_populates="config", uselist=False, lazy="joined")
    job = relationship("Job", back_populates="launch_config")

    __table_args__ = (
        Index(
            "uq_job_launch_config_active",
            "job_id",
            unique=True,
            postgresql_where=text(
                "job_id IS NOT NULL AND failed_at IS NULL AND completed_at IS NULL"
            ),
        ),
        CheckConstraint(
            "(container_repository IS NULL AND container_manifest_digest IS NULL "
            "AND NOT registry_scope_active AND registry_scope_revoked_at IS NULL) OR "
            "(server_id IS NOT NULL AND container_repository IS NOT NULL "
            "AND container_manifest_digest ~ '^sha256:[0-9a-f]{64}$' "
            "AND (((gpu_management_mode = 'miner') "
            "AND (registry_scope_active OR registry_scope_revoked_at IS NOT NULL)) "
            "OR ((gpu_management_mode IS DISTINCT FROM 'miner') "
            "AND NOT registry_scope_active AND registry_scope_revoked_at IS NULL)))",
            name="ck_launch_config_registry_scope",
        ),
        CheckConstraint(
            "(gpu_management_mode IS NULL AND gpu_launch_reservation_id IS NULL) OR "
            "(gpu_management_mode IN ('platform', 'miner') "
            "AND gpu_launch_reservation_id IS NOT NULL AND server_id IS NOT NULL)",
            name="ck_launch_config_gpu_manager",
        ),
        CheckConstraint(
            "compute_type IN ('cpu', 'gpu')",
            name="ck_launch_config_compute_type",
        ),
        CheckConstraint(
            "(miner_launch_request_id IS NULL "
            "AND miner_launch_request_sha256 IS NULL) OR "
            "(miner_launch_request_id ~ "
            "'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$' "
            "AND miner_launch_request_sha256 ~ '^[0-9a-f]{64}$')",
            name="ck_launch_config_miner_request_replay",
        ),
        Index(
            "uq_launch_configs_miner_request",
            "miner_hotkey",
            "miner_launch_request_id",
            unique=True,
            postgresql_where=text("miner_launch_request_id IS NOT NULL"),
        ),
        Index(
            "uq_launch_configs_gpu_reservation",
            "gpu_launch_reservation_id",
            unique=True,
            postgresql_where=text(
                "gpu_launch_reservation_id IS NOT NULL AND gpu_management_mode = 'platform'"
            ),
        ),
    )


_MINER_LAUNCH_REQUEST_IMMUTABLE_FUNCTION = DDL(
    """
    CREATE OR REPLACE FUNCTION enforce_miner_launch_request_immutable()
    RETURNS trigger LANGUAGE plpgsql AS $$
    BEGIN
        IF OLD.miner_launch_request_id IS DISTINCT FROM NEW.miner_launch_request_id
           OR OLD.miner_launch_request_sha256
              IS DISTINCT FROM NEW.miner_launch_request_sha256 THEN
            RAISE EXCEPTION
                'miner launch request identity is immutable for launch config %%',
                OLD.config_id;
        END IF;
        RETURN NEW;
    END;
    $$
    """
).execute_if(dialect="postgresql")

event.listen(
    LaunchConfig.__table__,
    "after_create",
    _MINER_LAUNCH_REQUEST_IMMUTABLE_FUNCTION,
)
event.listen(
    LaunchConfig.__table__,
    "after_create",
    DDL(
        """
        CREATE TRIGGER trg_miner_launch_request_immutable
        BEFORE UPDATE OF miner_launch_request_id, miner_launch_request_sha256
        ON launch_configs
        FOR EACH ROW EXECUTE FUNCTION enforce_miner_launch_request_immutable()
        """
    ).execute_if(dialect="postgresql"),
)


# ---------------------------------------------------------------------------
# Deployment lifecycle observability, driven entirely by ORM events on the models so the Prometheus
# counters AND the structured logs stay in lock-step with the tables -- no call-site instrumentation
# to keep in sync. Each lifecycle phase maps to a column transition:
#   LaunchConfig:  created -> after_insert; retrieved/verified -> *_at set; failed -> verification_error set
#   Instance:      created -> after_insert; activated -> activated_at set; deleted -> after_delete
# These 'set'/insert/delete events fire only on Python-level ORM operations, NOT on load/refresh, so
# reading an existing row never double-fires; each phase is reached at most once per row, so a simple
# "value is not None" guard suffices. State changes done via raw SQL (for DB-performance reasons)
# bypass these events -- instance verification (_mark_instance_verified), raw-SQL deletes (purge,
# chute bulk deletes), and the redis-based instance disable -- and are logged explicitly at those
# chokepoints instead.
# ---------------------------------------------------------------------------


def _safe_metric(fn, *args):
    """Run a metric update, never letting a metrics error break a deployment/verification path.

    A failure here is not expected and points at a problem in the metrics layer itself, so log it
    (WARNING) for visibility -- the stable "failed to record launch_config metric" prefix is a good
    thing to alert on -- rather than swallowing it silently.
    """
    try:
        fn(*args)
    except Exception as exc:
        logger.warning(
            f"failed to record launch_config metric via {getattr(fn, '__name__', fn)!r}: {exc}"
        )


@event.listens_for(LaunchConfig, "after_insert")
def _on_launch_config_created(mapper, connection, target):
    _safe_metric(launch_config_metrics.track_attempt, target.chute_id)
    launch_config_logger(target, event=LifecycleEvent.LAUNCH_CONFIG_CREATE).info(
        f"launch config created (deployment attempt): {target.config_id} (chute {target.chute_id})"
    )


@event.listens_for(LaunchConfig.retrieved_at, "set")
def _on_launch_config_retrieved(target, value, oldvalue, initiator):
    if value is not None:
        _safe_metric(launch_config_metrics.track_retrieved, target.chute_id)
        launch_config_logger(target, event=LifecycleEvent.LAUNCH_CONFIG_RETRIEVE).info(
            f"launch config retrieved by miner {target.miner_hotkey}: {target.config_id} (chute {target.chute_id})"
        )


@event.listens_for(LaunchConfig.verified_at, "set")
def _on_launch_config_verified(target, value, oldvalue, initiator):
    if value is not None:
        _safe_metric(launch_config_metrics.track_verified, target.chute_id)
        launch_config_logger(target, event=LifecycleEvent.LAUNCH_CONFIG_VERIFY).success(
            f"launch config verified: {target.config_id} (chute {target.chute_id})"
        )


@event.listens_for(LaunchConfig.verification_error, "set")
def _on_launch_config_failed(target, value, oldvalue, initiator):
    if value is not None:
        _safe_metric(launch_config_metrics.track_failure, target.chute_id, value)
        launch_config_logger(
            target, event=LifecycleEvent.LAUNCH_CONFIG_FAIL, verification_error=value
        ).warning(
            f"launch config verification failed: {target.config_id} (chute {target.chute_id}): {value}"
        )


@event.listens_for(Instance, "after_insert")
def _on_instance_created(mapper, connection, target):
    instance_logger(target, event=LifecycleEvent.INSTANCE_CREATE).info(
        f"instance created: {target.instance_id} (chute {target.chute_id}, miner {target.miner_hotkey})"
    )


@event.listens_for(Instance.activated_at, "set")
def _on_instance_activated(target, value, oldvalue, initiator):
    if value is not None:
        instance_logger(target, event=LifecycleEvent.INSTANCE_ACTIVATE).success(
            f"instance activated: {target.instance_id} (chute {target.chute_id})"
        )


@event.listens_for(Instance, "after_delete")
def _on_instance_deleted(mapper, connection, target):
    instance_logger(target, event=LifecycleEvent.INSTANCE_DELETE).warning(
        f"instance deleted: {target.instance_id} (chute {target.chute_id}, miner {target.miner_hotkey})"
    )
