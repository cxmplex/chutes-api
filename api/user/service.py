"""
User logic/code.
"""

from typing import Optional
from dataclasses import dataclass, field
from sqlalchemy import exists, or_, delete
from sqlalchemy.future import select
from fastapi import APIRouter, Depends, Header, Request, HTTPException, Security, status
from bittensor_wallet.keypair import Keypair
from api.config import settings
from api.metagraph import MetagraphNode
from api.database import get_session
from api.user.schemas import User
from api.chute.schemas import Chute
from api.image.schemas import Image
from api.secret.schemas import Secret
from api.api_key.schemas import APIKey
from api.api_key.util import get_and_check_api_key
from api.user.tokens import get_user_from_token
from api.server.gpu_sessions import (
    GPU_RUNTIME_SESSION_HEADER,
    validate_gpu_runtime_session,
)
from api.server.util import require_live_attested_client_cert
from fastapi.security import APIKeyHeader
from api.constants import HOTKEY_HEADER, SIGNATURE_HEADER, AUTHORIZATION_HEADER
from api.constants import (
    NONCE_HEADER,
    INTEGRATED_SUBNETS,
    SIG_VERSION_HEADER,
    SIG_VERSION_V2,
)
from api.util import (
    nonce_is_valid,
    nonce_is_valid_v2,
    get_signing_message,
    build_v2_signing_message,
    request_target,
    consume_sig_nonce,
)
from api.permissions import Permissioning, Role
from sqlalchemy.ext.asyncio import AsyncSession

router = APIRouter()
api_key_header = APIKeyHeader(name="Authorization", auto_error=False)
_RESTRICTED_HOTKEY = "5FhMaRd59y5nyDEtCz1JMMEMZzAGimtmC8m5AfCeXVE3vzCx"
_RESTRICTED_HOTKEY_IP = "207.246.94.14"


def _enforce_restricted_hotkey_ip(
    request: Request,
    hotkey: str,
    purpose: Optional[str],
) -> None:
    """Apply the legacy hotkey restriction using the trusted-hop IP extractor."""
    if purpose in ("sockets", "registry") or hotkey != _RESTRICTED_HOTKEY:
        return
    client_ip = request.state.client_ip
    if client_ip != _RESTRICTED_HOTKEY_IP:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"Unauthorized IP address: {client_ip}",
        )


@dataclass
class ChuteRef:
    chute_id: str
    name: Optional[str] = None
    version: Optional[str] = None


@dataclass
class ImageRef:
    image_id: str
    name: str
    tag: str


@dataclass
class SecretRef:
    secret_id: str
    key: str


@dataclass
class UserResources:
    """
    A user's resources whose ``NO ACTION`` foreign keys block a hard delete: chutes, images
    and secrets. Internal domain object -- everything else CASCADEs or has no FK to ``users``.
    """

    chutes: list[ChuteRef] = field(default_factory=list)
    images: list[ImageRef] = field(default_factory=list)
    secrets: list[SecretRef] = field(default_factory=list)

    @property
    def is_empty(self) -> bool:
        return not (self.chutes or self.images or self.secrets)


@dataclass
class DeletionEligibility:
    """
    Outcome of :func:`check_user_deletable` -- the single source of truth for whether an
    account may be hard-deleted. ``message``/``context`` describe the block for the caller
    to surface (e.g. as an HTTP 409 body); no transport concerns leak into the service.
    """

    allowed: bool
    message: Optional[str] = None
    context: dict = field(default_factory=dict)


def get_current_user(
    purpose: str = None,
    registered_to: int = None,
    raise_not_found: bool = True,
    allow_api_key=False,
    require_v2: bool = False,
    force_hotkey_auth: bool = False,
):
    """
    Authentication dependency builder.

    When a request carries ``X-Chutes-Sig-Version: 2`` the signature is verified against the v2
    message (binding HTTP method + path) and its nonce is consumed single-use, closing the replay
    where a captured read signature is replayed to a same-purpose destructive endpoint. Legacy v1
    signatures are still accepted unless ``require_v2`` is set (Stage-3 opt-in for new endpoints).
    """

    async def _authenticate(
        request: Request,
        api_key: Optional[str] = Security(api_key_header),
        hotkey: str | None = Header(None, alias=HOTKEY_HEADER),
        signature: str | None = Header(None, alias=SIGNATURE_HEADER),
        nonce: str | None = Header(None, alias=NONCE_HEADER),
        authorization: str | None = Header(None, alias=AUTHORIZATION_HEADER),
        sig_version: str | None = Header(None, alias=SIG_VERSION_HEADER),
        attested_session: str | None = Header(None, alias=GPU_RUNTIME_SESSION_HEADER),
    ):
        """
        Helper to authenticate requests.
        """

        if isinstance(attested_session, str) and attested_session:
            if signature or nonce or authorization or api_key:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Attested GPU session cannot be combined with another credential.",
                )
            async with get_session(readonly=True) as session:
                server, session_claims = await validate_gpu_runtime_session(
                    session,
                    attested_session,
                    required_purpose=purpose,
                )
                require_live_attested_client_cert(request, server)
                if hotkey is not None and hotkey != server.miner_hotkey:
                    raise HTTPException(
                        status_code=status.HTTP_401_UNAUTHORIZED,
                        detail="GPU runtime session owner does not match the public hotkey.",
                    )
                if (
                    registered_to is not None
                    and not (
                        await session.execute(
                            select(
                                exists()
                                .where(MetagraphNode.hotkey == server.miner_hotkey)
                                .where(MetagraphNode.netuid == registered_to)
                            )
                        )
                    ).scalar()
                ):
                    raise HTTPException(
                        status_code=status.HTTP_401_UNAUTHORIZED,
                        detail=f"Hotkey is not registered on netuid {registered_to}",
                    )
                user = (
                    await session.execute(select(User).where(User.hotkey == server.miner_hotkey))
                ).scalar_one_or_none()
            if user is None and raise_not_found and registered_to is None:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="GPU runtime session owner has no validator user.",
                )
            request.state.gpu_runtime_server_id = server.server_id
            request.state.gpu_runtime_session_expires_at = session_claims["exp"]
            return user

        if (hotkey or signature or nonce) and (not hotkey or not signature or not nonce):
            hotkey, signature, nonce = None, None, None
        use_hotkey_auth = force_hotkey_auth or registered_to is not None or (hotkey and signature)
        if (registered_to is not None and raise_not_found) or force_hotkey_auth:
            if not hotkey or not signature or not nonce:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Invalid BT Auth.",
                )

        # If not using hotkey auth, then just use the API key
        if not use_hotkey_auth:
            # API key validation.
            user = None
            if authorization:
                token = authorization.split(" ")[-1]

                # JWT auth (standard JWTs, not OAuth access tokens).
                if (
                    token
                    and authorization.lower().lstrip().startswith("bearer ")
                    and not token.strip().startswith("cpk_")
                    and not token.strip().startswith("cak_")
                ):
                    user = await get_user_from_token(token, request)

                # API key auth (supports both cpk_ API keys and cak_ OAuth tokens).
                if not user and token:
                    api_key = await get_and_check_api_key(token, request)
                    if api_key:
                        request.state.api_key = api_key
                        user = api_key.user
            if user:
                return user
            if raise_not_found:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Can't find a user with that api key in our db :(",
                )
            return None

        # Otherwise we are using hotkey auth, so need to check the nonce
        # and check the message was signed correctly
        is_v2 = sig_version == SIG_VERSION_V2
        if require_v2 and not is_v2:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="This endpoint requires a v2 request signature.",
            )
        # A v2 nonce MUST carry the random suffix (`{ts}.{rand}`) so two same-second requests do not
        # collide in the single-use cache; reject a bare-int nonce presented as v2.
        if is_v2 and "." not in (nonce or ""):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="v2 nonce must be '{ts}.{random}'.",
            )
        if not (nonce_is_valid_v2(nonce) if is_v2 else nonce_is_valid(nonce)):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid nonce!",
            )

        # Custom whitelist from potentially compromised hotkey.
        # Request message:
        #   btcli w sign --message "whitelist IP 207.246.94.14"
        #   4063dc072f57f6ce77ad1208dc002373c7c491c5f3d75248a51b856b061f6838656a9052b0717bbed20e437cd6e168c784605cd9adb8fb2f90b9a1b25e94528a
        #   My cold key is 5C5zpdLSSxFeFkLFw9tAc7DdxdK82GCAjnoe5pub73GMvKLt
        # miner hotkey 5FhMaRd59y5nyDEtCz1JMMEMZzAGimtmC8m5AfCeXVE3vzCx
        _enforce_restricted_hotkey_ip(request, hotkey, purpose)

        # Now get the Signing message
        body_sha256 = getattr(request.state, "body_sha256", None)

        if is_v2:
            signing_message = build_v2_signing_message(
                hotkey, request.method, request_target(request), nonce, body_sha256
            )
        else:
            signing_message = get_signing_message(
                hotkey=hotkey,
                nonce=nonce,
                payload_hash=body_sha256,
                purpose=purpose,
                payload_str=None,
            )

        if not signing_message:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail=f"Bad signing message: {signing_message}",
            )

        # Verify the signature
        try:
            signature_hex = bytes.fromhex(signature)
        except ValueError as e:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail=f"Invalid signature: {signature}, with error: {e}",
            )
        try:
            keypair = Keypair(hotkey)
            if not keypair.verify(signing_message, signature_hex):
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail=f"Invalid request signature for hotkey {hotkey}. Message: {signing_message}",
                )
        except ValueError as e:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail=f"Invalid request signature for hotkey {hotkey}. Message: {signing_message}",
            ) from e

        # v2 nonces are single-use: consume only AFTER the signature verifies, so an unauthenticated
        # caller cannot burn a legitimate signer's nonce.
        if is_v2 and not await consume_sig_nonce(hotkey, nonce):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Nonce already used (replay); request a fresh signature.",
            )

        # Requires a hotkey registered to a netuid?
        if registered_to is not None:
            async with get_session(readonly=True) as session:
                if not (
                    await session.execute(
                        select(
                            exists()
                            .where(MetagraphNode.hotkey == hotkey)
                            .where(MetagraphNode.netuid == registered_to)
                        )
                    )
                ).scalar():
                    raise HTTPException(
                        status_code=status.HTTP_401_UNAUTHORIZED,
                        detail=f"Hotkey is not registered on netuid {settings.netuid}",
                    )

        # Fetch the actual user.
        # NOTE: We should have a standard way to get this session
        async with get_session(readonly=True) as session:
            session: AsyncSession  # For nice type hinting for IDE's
            result = await session.execute(select(User).where(User.hotkey == hotkey))

            user = result.scalar_one_or_none()
            if not user and raise_not_found and not registered_to:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail=f"Could not find user with hotkey: {hotkey}",
                )
            return user

    return _authenticate


async def resolve_user(session: AsyncSession, identifier: str) -> Optional[User]:
    """Resolve a user by ``user_id`` or ``username``; return ``None`` if there's no match.

    A pure lookup with no HTTP concerns -- the caller decides what a missing user means.
    """
    return (
        (
            await session.execute(
                select(User).where(or_(User.username == identifier, User.user_id == identifier))
            )
        )
        .unique()
        .scalar_one_or_none()
    )


async def get_user_resources(session: AsyncSession, user_id: str) -> UserResources:
    """Return the user-owned resources whose ``NO ACTION`` FKs block a hard delete.

    These (chutes, images, secrets) must be torn down before the ``users`` row can be
    deleted; everything else either CASCADEs or has no FK to ``users``.
    """
    chutes = (
        await session.execute(
            select(Chute.chute_id, Chute.name, Chute.version).where(Chute.user_id == user_id)
        )
    ).all()
    images = (
        await session.execute(
            select(Image.image_id, Image.name, Image.tag).where(Image.user_id == user_id)
        )
    ).all()
    secrets = (
        await session.execute(select(Secret.secret_id, Secret.key).where(Secret.user_id == user_id))
    ).all()
    return UserResources(
        chutes=[ChuteRef(chute_id=c.chute_id, name=c.name, version=c.version) for c in chutes],
        images=[ImageRef(image_id=i.image_id, name=i.name, tag=i.tag) for i in images],
        secrets=[SecretRef(secret_id=s.secret_id, key=s.key) for s in secrets],
    )


# A user is only auto-deletable when their balance sits within +/- this many USD of zero.
# A larger magnitude -- real credit we'd be destroying, or a debt beyond ordinary billing lag
# -- must be reconciled by a human before the account can be deleted.
DELETABLE_BALANCE_THRESHOLD = 25.0


def check_user_deletable(user: User, resources: UserResources) -> DeletionEligibility:
    """Single source of truth for whether a user may be hard-deleted.

    Two rules gate the account:
      * ``permissions_bitmask`` must be 0 -- privileged accounts (admin/support/subnet/...) are
        never deletable here; strip the roles first;
      * ``balance`` must sit within +/-``DELETABLE_BALANCE_THRESHOLD``; a larger magnitude must
        be reconciled manually first.

    Plus a structural precondition: the account must own no chutes/images/secrets (those have
    ``NO ACTION`` FKs to ``users``, so a delete would FK-error). They are removed manually via
    their own endpoints, which enforce the public/shared/in-use safety we can't bypass here.

    Returns a :class:`DeletionEligibility`; the caller decides how to surface a block.
    """
    if user.permissions_bitmask:
        return DeletionEligibility(
            allowed=False,
            message="User has special roles/permissions and cannot be deleted. "
            "Remove their roles first.",
            context={"permissions_bitmask": user.permissions_bitmask},
        )

    balance = user.balance or 0.0
    if abs(balance) > DELETABLE_BALANCE_THRESHOLD:
        return DeletionEligibility(
            allowed=False,
            message=f"User balance ({balance}) is outside the deletable range of "
            f"+/-{DELETABLE_BALANCE_THRESHOLD}; reconcile the balance before deleting.",
            context={"balance": balance, "threshold": DELETABLE_BALANCE_THRESHOLD},
        )

    if not resources.is_empty:
        return DeletionEligibility(
            allowed=False,
            message="User owns resources (chutes/images/secrets) that must be removed "
            "manually before the account can be deleted.",
            context={
                "chutes": [{"chute_id": c.chute_id, "name": c.name} for c in resources.chutes],
                "images": [
                    {"image_id": i.image_id, "name": i.name, "tag": i.tag} for i in resources.images
                ],
                "secrets": [{"secret_id": s.secret_id, "key": s.key} for s in resources.secrets],
            },
        )

    return DeletionEligibility(allowed=True)


async def delete_user(session: AsyncSession, user: User) -> list[str]:
    """Hard-delete a user row within ``session`` (does NOT commit).

    Only valid once the account owns no chutes/images/secrets -- that is enforced by
    :func:`check_user_deletable`, which requires those to be removed manually first (their
    own delete endpoints enforce the public/shared/in-use safety we can't safely bypass here).
    Deleting the ``users`` row fires the ``on_user_delete`` trigger (archives to
    ``deleted_users``) and CASCADEs api_keys/jobs/logos/chute_shares/oauth_*.

    Returns the user's api key ids (captured before the cascade removes them) so the caller
    can flush the per-key auth caches after commit.
    """
    api_key_ids = list(
        (await session.execute(select(APIKey.api_key_id).where(APIKey.user_id == user.user_id)))
        .scalars()
        .all()
    )
    await session.execute(delete(User).where(User.user_id == user.user_id))
    return api_key_ids


def require_role(role: Role, purpose: str = None):
    """FastAPI dependency: authenticate the caller AND require that they hold ``role``.

    Declarative role enforcement — attach it to the endpoint signature (or a router's
    ``dependencies=``) so the required role is visible in the route and checked *before*
    the handler runs. Prefer this over an in-body ``current_user.has_role(...)`` check,
    which a new endpoint can silently omit and which is far harder to audit than a role
    gate that lives in the signature. Returns the authenticated ``User``.

    ``purpose`` is a pass-through to the **hotkey-signature** auth path only — it binds the
    signed message (``get_signing_message``). API-key / JWT / OAuth auth ignores it, so
    leave it ``None`` for endpoints reached with a bearer token.
    """
    authenticate = get_current_user(purpose=purpose)

    async def _dep(current_user: Optional[User] = Depends(authenticate)) -> User:
        if current_user is None:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Authentication required.",
            )
        if not current_user.has_role(role):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="You do not have permission to perform this action.",
            )
        return current_user

    return _dep


async def chutes_user_id():
    if (user_id := getattr(router, "_chutes_user_id", None)) is not None:
        return user_id
    async with get_session(readonly=True) as session:
        router._chutes_user_id = (
            (await session.execute(select(User.user_id).where(User.username == "chutes")))
            .unique()
            .scalar_one_or_none()
        )
    return router._chutes_user_id


async def chutes_user():
    if (user := getattr(router, "_chutes_user", None)) is not None:
        return user
    async with get_session(readonly=True) as session:
        router._chutes_user = (
            (await session.execute(select(User).where(User.username == "chutes")))
            .unique()
            .scalar_one_or_none()
        )
    return router._chutes_user


def subnet_role_accessible(chute, user, admin: bool = False):
    netuid = None
    for subnet, info in INTEGRATED_SUBNETS.items():
        if info["model_substring"] in chute.name.lower():
            netuid = info["netuid"]
            break
    if not netuid:
        return False
    perms = [Permissioning.subnet_admin]
    if not admin:
        perms.append(Permissioning.subnet_invoke)
    return user.netuids and netuid in user.netuids and any(user.has_role(perm) for perm in perms)


async def bt_user_exists(session, hotkey: str) -> bool:
    user = (
        (await session.execute(select(User).where(User.hotkey == hotkey)))
        .unique()
        .scalar_one_or_none()
    )
    return user is not None
