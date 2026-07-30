"""
Main API entrypoint.
"""

import api.logging_bootstrap  # noqa: F401  # configure structured logging before imports log
import os
import re
import gc
import asyncio

# import fickling
import hashlib
from loguru import logger
from contextlib import asynccontextmanager
from fastapi import FastAPI, Request, APIRouter, HTTPException, status, Response
from fastapi.responses import ORJSONResponse
from sqlalchemy import text
import api.database.orms  # noqa: F401
from prometheus_client import (
    generate_latest,
    CollectorRegistry,
    multiprocess,
    CONTENT_TYPE_LATEST,
)
from prometheus_fastapi_instrumentator import Instrumentator
from concurrent.futures import ThreadPoolExecutor
from api.api_key.router import router as api_key_router
from api.api_key.storage_scope import storage_authorization_scope
from api.chute.router import router as chute_router
from api.bounty.router import router as bounty_router
from api.image.router import router as image_router
from api.invocation.router import router as invocation_router
from api.invocation.router import host_invocation_router
from api.registry.router import router as registry_router
from api.user.router import router as user_router
from api.node.router import router as node_router
from api.instance.router import router as instance_router
from api.payment.router import router as payment_router
from api.miner.router import router as miner_router
from api.logo.router import router as logo_router
from api.job.router import router as jobs_router
from api.secret.router import router as secrets_router
from api.guesser import router as guess_router
from api.audit.router import router as audit_router
from api.server.router import router as servers_router
from api.host.router import router as hosts_router
from api.storage.router import router as storage_router
from api.releases.router import router as releases_router
from api.misc.router import router as misc_router
from api.idp.router import router as idp_router
from api.e2e.router import router as e2e_router
from api.encrypted_logs.router import router as encrypted_logs_router
from api.model_alias.router import router as model_alias_router
from api.chute.util import chute_id_by_slug
from api.database import get_session
from api.database.migrations import run_database_migrations
from api.config import settings
from api.metrics.util import keep_gauges_fresh
from api.instance.util import start_instance_invalidation_listener
from api.log import install_asyncio_exception_handler
from api.client_ip import resolve_client_ip
from api.storage.startup import require_chutefs_token_key_retention
from api.gpu_registration_keys import (
    require_gpu_registration_recovery_key_retention,
)


async def loop_lag_monitor(interval: float = 0.1, warn_threshold: float = 0.2):
    """
    Very lightweight event-loop lag monitor.
    Produces *summary only* — no full stack traces.
    """
    loop = asyncio.get_running_loop()
    last = loop.time()

    ignored_task_str = (
        "aiohttp",
        "ClientSession",
        "ClientResponse",
        "TCPConnector",
    )

    def _should_ignore(task: asyncio.Task) -> bool:
        r = repr(task)
        return any(s in r for s in ignored_task_str)

    while True:
        await asyncio.sleep(interval)
        now = loop.time()
        lag = now - last - interval
        last = now

        if lag <= warn_threshold:
            continue

        ms = lag * 1000.0
        tasks = [
            t
            for t in asyncio.all_tasks(loop)
            if t is not asyncio.current_task(loop=loop) and not _should_ignore(t)
        ]

        # Group tasks by coroutine/function name (high-level signal)
        summary = {}
        for t in tasks:
            coro = t.get_coro()
            name = getattr(coro, "__qualname__", coro.__class__.__name__)
            summary.setdefault(name, 0)
            summary[name] += 1
        logger.warning(f"Event loop lag: {ms:.1f}ms, task summary during lag: {summary}")


@asynccontextmanager
async def lifespan(_: FastAPI):
    """
    Execute all initialization/startup code, e.g. ensuring tables exist and such.
    """
    gc.set_threshold(5000, 50, 50)
    install_asyncio_exception_handler()

    trust_health = settings.tee_measurement_health()
    if not trust_health["ready"]:
        raise RuntimeError(
            f"TEE measurement trust set is not ready at startup: {trust_health['last_error']}"
        )

    await run_database_migrations()
    await require_chutefs_token_key_retention()

    loop = asyncio.get_event_loop()
    executor = ThreadPoolExecutor(max_workers=64)
    loop.set_default_executor(executor)

    asyncio.create_task(loop_lag_monitor())
    asyncio.create_task(keep_gauges_fresh())
    asyncio.create_task(start_instance_invalidation_listener())

    # Prom multi-proc dir.
    os.makedirs("/tmp/prometheus_multiproc", exist_ok=True)

    # Every worker starts the loop. The session-level PostgreSQL advisory lock elects exactly one
    # worker for each bounded pass and cannot be orphaned by a stale container-local pid file.
    from api.storage.reconcile import storage_reconcile_loop

    asyncio.create_task(storage_reconcile_loop())

    yield


app = FastAPI(default_response_class=ORJSONResponse, lifespan=lifespan)

os.makedirs("/tmp/prometheus_multiproc", exist_ok=True)
Instrumentator(
    should_instrument_requests_inprogress=True,
    inprogress_name="http_requests_inprogress",
    inprogress_labels=False,
).instrument(app)

default_router = APIRouter()
default_router.include_router(user_router, prefix="/users", tags=["Users"])
default_router.include_router(chute_router, prefix="/chutes", tags=["Chutes"])
default_router.include_router(bounty_router, prefix="/bounties", tags=["Chutes"])
default_router.include_router(image_router, prefix="/images", tags=["Images"])
default_router.include_router(node_router, prefix="/nodes", tags=["Nodes"])
default_router.include_router(payment_router, tags=["Pricing", "Payments"])
default_router.include_router(instance_router, prefix="/instances", tags=["Instances"])
default_router.include_router(invocation_router, prefix="/invocations", tags=["Invocations"])
default_router.include_router(registry_router, prefix="/registry", tags=["Authentication"])
default_router.include_router(api_key_router, prefix="/api_keys", tags=["Authentication"])
default_router.include_router(miner_router, prefix="/miner", tags=["Miner"])
default_router.include_router(logo_router, prefix="/logos", tags=["Logo"])
default_router.include_router(guess_router, prefix="/guess", tags=["ConfigGuesser"])
default_router.include_router(audit_router, prefix="/audit", tags=["Audit"])
default_router.include_router(jobs_router, prefix="/jobs", tags=["Job"])
default_router.include_router(secrets_router, prefix="/secrets", tags=["Secret"])
default_router.include_router(misc_router, prefix="/misc", tags=["Miscellaneous"])
default_router.include_router(servers_router, prefix="/servers", tags=["Servers"])
default_router.include_router(hosts_router, prefix="/hosts", tags=["Hosts"])
default_router.include_router(storage_router, prefix="/storage", tags=["Storage"])
default_router.include_router(releases_router, prefix="/releases", tags=["Releases"])
default_router.include_router(idp_router, prefix="/idp", tags=["Identity Provider"])
default_router.include_router(e2e_router, prefix="/e2e", tags=["E2E Encryption"])
default_router.include_router(
    encrypted_logs_router, prefix="/encrypted_logs", tags=["Encrypted Logs"]
)
default_router.include_router(model_alias_router, prefix="/model_aliases", tags=["Model Aliases"])


# Do not use app for this, else middleware picks it up
async def ping():
    try:
        async with get_session() as session:
            await session.execute(text("SELECT 1"))
        async with get_session(readonly=True) as session:
            await session.execute(text("SELECT 1"))
        return {"message": "pong"}
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=f"Database connectivity problems: {str(e)}",
        )


async def ready(request: Request):
    """Internal readiness surface: database plus complete TEE trust-set health."""
    if request.state.has_resolved_ip:
        raise HTTPException(status_code=403, detail="Forbidden")
    trust_health = settings.tee_measurement_health()
    if not trust_health["ready"]:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail={"tee_measurements": trust_health},
        )
    try:
        # Kubernetes calls readiness periodically on every serving pod. This is
        # also the bounded per-replica acknowledgement path for epochs staged
        # after a rolling key distribution, so activation never needs a restart.
        await require_chutefs_token_key_retention()
        await require_gpu_registration_recovery_key_retention()
        async with get_session() as session:
            await session.execute(text("SELECT 1"))
        async with get_session(readonly=True) as session:
            await session.execute(text("SELECT 1"))
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=f"Database connectivity problems: {exc}",
        ) from exc
    return {"status": "ready", "tee_measurements": trust_health}


def _tee_trust_metrics(health: dict) -> bytes:
    """Render bounded operator-only trust-load state without registering stale label series."""

    def escape(value) -> str:
        return (
            str(value if value is not None else "")
            .replace("\\", "\\\\")
            .replace("\n", "\\n")
            .replace('"', '\\"')
        )

    labels = (
        f'status="{escape(health.get("status"))}",'
        f'fingerprint="{escape(health.get("fingerprint"))}",'
        f'last_error="{escape(health.get("last_error"))}"'
    )
    return (
        "# HELP chutes_tee_measurement_trust_info Current atomic TEE trust-load state.\n"
        "# TYPE chutes_tee_measurement_trust_info gauge\n"
        f"chutes_tee_measurement_trust_info{{{labels}}} 1\n"
        "# HELP chutes_tee_measurement_trust_ready Whether the complete configured trust set loaded.\n"
        "# TYPE chutes_tee_measurement_trust_ready gauge\n"
        f"chutes_tee_measurement_trust_ready {1 if health.get('ready') else 0}\n"
        "# HELP chutes_tee_measurement_trust_entries Active last-known-good measurement entries.\n"
        "# TYPE chutes_tee_measurement_trust_entries gauge\n"
        f"chutes_tee_measurement_trust_entries {int(health.get('measurement_count') or 0)}\n"
    ).encode()


# Prometheus metrics endpoint.
async def get_latest_metrics(request: Request):
    if request.state.has_resolved_ip:
        raise HTTPException(status_code=403, detail="Forbidden")
    trust_health = settings.tee_measurement_health()
    registry = CollectorRegistry()
    multiprocess.MultiProcessCollector(registry)
    data = generate_latest(registry) + _tee_trust_metrics(trust_health)
    return Response(data, media_type=CONTENT_TYPE_LATEST)


default_router.get("/ping")(ping)
default_router.get("/readyz")(ready)
default_router.get("/_metrics")(get_latest_metrics)


# OpenID Connect discovery endpoint at root level (standard location)
@default_router.get("/.well-known/openid-configuration")
async def openid_configuration_root(request: Request):
    """
    OpenID Connect Discovery endpoint.
    """
    from api.idp.schemas import get_available_scopes

    idp_base = f"https://api.{settings.base_domain}/idp"

    return {
        "issuer": f"https://api.{settings.base_domain}",
        "authorization_endpoint": f"{idp_base}/authorize",
        "token_endpoint": f"{idp_base}/token",
        "userinfo_endpoint": f"{idp_base}/userinfo",
        "revocation_endpoint": f"{idp_base}/token/revoke",
        "introspection_endpoint": f"{idp_base}/token/introspect",
        "scopes_supported": list(get_available_scopes().keys()),
        "response_types_supported": ["code"],
        "response_modes_supported": ["query"],
        "grant_types_supported": ["authorization_code", "refresh_token"],
        "token_endpoint_auth_methods_supported": [
            "client_secret_post",
            "client_secret_basic",
            "none",
        ],
        "code_challenge_methods_supported": ["plain", "S256"],
        "service_documentation": "https://docs.chutes.ai/oauth",
        "subject_types_supported": ["public"],
        "claims_supported": [
            "sub",
            "username",
            "created_at",
        ],
    }


app.include_router(default_router)
app.include_router(host_invocation_router)

# Pickle safety checks.
# fickling.always_check_safety()


@app.middleware("http")
async def host_router_middleware(request: Request, call_next):
    """
    Route differentiation for hostname-based simple invocations.
    """
    try:
        request.state.client_ip, request.state.has_resolved_ip = resolve_client_ip(request)
    except HTTPException as exc:
        # Exceptions raised from user middleware bypass FastAPI's exception handlers and can
        # otherwise surface as a 500 from Starlette's middleware stack.
        return ORJSONResponse(
            status_code=exc.status_code,
            content={"detail": exc.detail},
            headers=exc.headers,
        )

    if request.url.path == "/ping":
        app.router = default_router
        return await call_next(request)
    request.state.chute_id = None
    request.state.free_invocation = False
    host = request.headers.get("host", "")
    host_parts = re.search(r"^([a-z0-9-]+)\.[a-z0-9-]+", host.lower())

    # Slug overrides, if any.
    slug = host_parts.group(1).lower() if host_parts else None
    if slug == "chutes-qwen-qwen3-embedding-8b":
        slug = "chutes-qwen-qwen3-embedding-8b-tee"

    # MEGALLM
    if (
        host_parts
        and host_parts.group(1) == "llm"
        and (request.method.lower() == "post" or request.url.path == "/v1/models")
    ):
        request.state.chute_id = "__megallm__"
        request.state.auth_method = "invoke"
        request.state.auth_object_type = "chutes"
        request.state.auth_object_id = "__megallm__"
        app.router = host_invocation_router

    # MEGAEMBED
    elif host_parts and host_parts.group(1) == "embed" and request.method.lower() == "post":
        request.state.chute_id = "__megaembed__"
        request.state.auth_method = "invoke"
        request.state.auth_object_type = "chutes"
        request.state.auth_object_id = "__megaembed__"
        app.router = host_invocation_router

    # MEGADIFFUSER
    elif host_parts and host_parts.group(1) == "image" and request.method.lower() == "post":
        request.state.chute_id = "__megadiffuser__"
        request.state.auth_method = "invoke"
        request.state.auth_object_type = "chutes"
        request.state.auth_object_id = "__megadiffuser__"
        app.router = host_invocation_router

    # Hostname based router.
    elif host_parts and host_parts.group(1) != "api" and (chute_id := await chute_id_by_slug(slug)):
        request.state.chute_id = chute_id
        request.state.auth_method = "invoke"
        request.state.auth_object_type = "chutes"
        request.state.auth_object_id = chute_id
        app.router = host_invocation_router

    # Normal router.
    else:
        request.state.auth_method = "read"
        if request.method.lower() in ("post", "put", "patch"):
            request.state.auth_method = "write"
        elif request.method.lower() == "delete":
            request.state.auth_method = "delete"

        # Invocations are special.
        if request.method.lower() == "post":
            inv_match = re.match(r"^/chutes/([^/]+)/(.+)$", request.url.path, re.I)
            if inv_match:
                chute_id = inv_match.group(1)
                request.state.auth_method = "invoke"
                request.state.chute_id = chute_id
                request.state.auth_object_id = chute_id
                request.state.auth_object_type = "chutes"

        # E2E endpoints are chute invocations for OAuth scope purposes.
        if request.state.auth_method != "invoke":
            if request.url.path.startswith("/e2e/instances/"):
                chute_id = request.url.path.split("/")[3]
                request.state.auth_method = "invoke"
                request.state.chute_id = chute_id
                request.state.auth_object_id = chute_id
                request.state.auth_object_type = "chutes"
            elif request.method.lower() == "post" and request.url.path == "/e2e/invoke":
                chute_id = request.headers.get("x-chute-id") or "__list_or_invalid__"
                request.state.auth_method = "invoke"
                request.state.chute_id = chute_id
                request.state.auth_object_id = chute_id
                request.state.auth_object_type = "chutes"

        if request.state.auth_method != "invoke":
            # Handle /users/me/* paths specially for OAuth scope checking
            if request.url.path.startswith("/users/me"):
                if "/balance" in request.url.path:
                    request.state.auth_object_type = "billing"
                elif "/quota" in request.url.path:
                    request.state.auth_object_type = "account"
                else:
                    request.state.auth_object_type = "account"
                request.state.auth_object_id = "__self__"
            elif request.url.path.startswith("/storage/"):
                request.state.auth_object_type = "storage"
                (
                    request.state.auth_method,
                    request.state.auth_object_id,
                ) = await storage_authorization_scope(request)
            else:
                request.state.auth_object_type = request.url.path.split("/")[-1]
                # XXX at some point, perhaps we can support objects by name too, but for
                # now, for auth to work (easily) we just need to only support UUIDs when
                # using API keys.
                path_match = re.match(r"^/[^/]+/([^/]+)$", request.url.path)
                if path_match:
                    request.state.auth_object_id = path_match.group(1)
                else:
                    request.state.auth_object_id = "__list_or_invalid__"
        app.router = default_router
    return await call_next(request)


@app.middleware("http")
async def request_body_checksum(request: Request, call_next):
    if request.method in ["POST", "PUT", "PATCH"]:
        body = await request.body()
        sha256_hash = hashlib.sha256(body).hexdigest()
        request.state.body_sha256 = sha256_hash
    else:
        request.state.body_sha256 = None
    return await call_next(request)
