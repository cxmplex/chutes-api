import time
import json
from loguru import logger
from datetime import datetime, timezone
from typing import Optional
from api.chute.schemas import Chute
from api.config import settings
from metasync.constants import (
    BOUNTY_BOOST_MIN,
    BOUNTY_BOOST_MAX,
    BOUNTY_BOOST_RAMP_MINUTES,
)
from api.constants import (
    BOUNTY_COOLDOWN_SECONDS,
    BOUNTY_LIFETIME_PUBLIC,
    BOUNTY_LIFETIME_PRIVATE,
    BOUNTY_LIFETIME_AFFINE,
)
from api.metrics.warmup import track_warmup_request, WarmupTrigger


# Key prefix for bounty timestamps (v2 format: plain timestamp string)
BOUNTY_KEY_PREFIX = "bounty_v2:"


CLAIM_BOUNTY_LUA = """
local bounty_key = KEYS[1]
local bounty_data = redis.call('GET', bounty_key)
if bounty_data then
    redis.call('DEL', bounty_key)
    return bounty_data
else
    return nil
end
"""

# SafeRedis shields timed-out operations, so the Lua script can finish after the
# caller has received no response. Cache the exact atomic consume result long
# enough for the persisted activation attempt to recover it on retry.
ACTIVATION_REPLAY_TTL_SECONDS = 24 * 60 * 60

CLAIM_BOUNTY_REPLAY_LUA = """
local bounty_key = KEYS[1]
local replay_key = KEYS[2]
local cooldown_key = KEYS[3]
local attempt_id = ARGV[1]
local replay_ttl = ARGV[2]
local cooldown_ttl = ARGV[3]
local chute_id = ARGV[4]

local cached = redis.call('GET', replay_key)
if cached then
    return cached
end

local bounty_data = redis.call('GET', bounty_key)
local now = redis.call('TIME')
local claimed_at = tonumber(now[1]) + (tonumber(now[2]) / 1000000)
local envelope

if bounty_data then
    local created_at = tonumber(bounty_data)
    if not created_at then
        return redis.error_reply('invalid bounty timestamp')
    end
    local age_seconds = math.floor(claimed_at - created_at)
    if age_seconds < 0 then
        age_seconds = 0
    end
    local amount = math.min((3 * age_seconds) + 100, 86400)
    envelope = cjson.encode({
        schema = 'chutes.activation-bounty-result.v1',
        attempt_id = attempt_id,
        chute_id = chute_id,
        claimed_at = claimed_at,
        bounty = {
            amount = amount,
            created_at = created_at,
            age_seconds = age_seconds
        }
    })
    redis.call('DEL', bounty_key)
    redis.call('SET', cooldown_key, '1', 'EX', cooldown_ttl)
else
    envelope = cjson.encode({
        schema = 'chutes.activation-bounty-result.v1',
        attempt_id = attempt_id,
        chute_id = chute_id,
        claimed_at = claimed_at,
        bounty = cjson.null
    })
end

redis.call('SET', replay_key, envelope, 'EX', replay_ttl)
return envelope
"""

CREATE_BOUNTY_LUA = """
local bounty_key = KEYS[1]
local bounty_data = ARGV[1]
local expire_time = ARGV[2]
if redis.call('EXISTS', bounty_key) == 0 then
    redis.call('SET', bounty_key, bounty_data, 'EX', expire_time)
    return 1
else
    return 0
end
"""


def _bounty_key(chute_id: str) -> str:
    return f"{BOUNTY_KEY_PREFIX}{chute_id}"


def _activation_bounty_replay_key(attempt_id: str) -> str:
    return f"activation_bounty_result:{attempt_id}"


def _parse_activation_claim_envelope(data, attempt_id: str, chute_id: str) -> dict:
    if data is None:
        raise RuntimeError(
            "Activation bounty claim returned no durable result; retry the same attempt"
        )
    try:
        if isinstance(data, bytes):
            data = data.decode()
        envelope = json.loads(data)
    except (TypeError, ValueError, UnicodeDecodeError) as exc:
        raise RuntimeError(
            "Activation bounty claim returned an invalid envelope"
        ) from exc
    if (
        not isinstance(envelope, dict)
        or envelope.get("schema") != "chutes.activation-bounty-result.v1"
        or envelope.get("attempt_id") != attempt_id
        or envelope.get("chute_id") != chute_id
        or "bounty" not in envelope
    ):
        raise RuntimeError("Activation bounty claim envelope identity mismatch")
    bounty = envelope["bounty"]
    if bounty is not None and (
        not isinstance(bounty, dict)
        or not isinstance(bounty.get("amount"), (int, float))
        or not isinstance(bounty.get("created_at"), (int, float))
        or not isinstance(bounty.get("age_seconds"), (int, float))
    ):
        raise RuntimeError("Activation bounty claim envelope payload is invalid")
    return envelope


def _parse_timestamp(data) -> Optional[float]:
    """Parse bounty timestamp from Redis data (plain float string)."""
    if data is None:
        return None
    try:
        if isinstance(data, bytes):
            data = data.decode()
        return float(data)
    except (TypeError, ValueError):
        return None


async def is_chute_disabled(chute_id: str) -> bool:
    """
    Lightweight check if a chute is disabled using Redis cache.
    """
    try:
        disabled = await settings.lite_redis_client.get(f"chute_disabled:{chute_id}")
        return int(disabled) == 1
    except Exception:
        return False


async def set_chute_disabled(chute_id: str, disabled: bool):
    """
    Set or clear the disabled flag for a chute in Redis.
    """
    key = f"chute_disabled:{chute_id}"
    try:
        if disabled:
            await settings.lite_redis_client.set(key, "1")
        else:
            await settings.lite_redis_client.delete(key)
    except Exception as exc:
        logger.warning(f"Failed to set chute disabled state: {exc}")


async def bounty_lifetime_for(chute: Chute) -> int:
    """
    Seconds a bounty -- and the matching explicit-warmup demand window -- stays open for this chute.

    Public chutes keep a long window; private non-legacy chutes get a short one so users aren't
    billed for idle time (affine chutes a bit longer). Used by both the bounty-creation path and the
    warmup request->hot correlation key so the two TTLs never drift.
    """
    # Imported lazily to avoid an import cycle (api.util / api.user.service pull in bounty helpers).
    from api.util import has_legacy_private_billing
    from api.user.service import chutes_user_id

    if (
        not chute.public
        and not has_legacy_private_billing(chute)
        and chute.user_id != await chutes_user_id()
    ):
        return (
            BOUNTY_LIFETIME_AFFINE
            if "/affine" in chute.name.lower()
            else BOUNTY_LIFETIME_PRIVATE
        )
    return BOUNTY_LIFETIME_PUBLIC


async def create_bounty_if_not_exists(chute_id: str, lifetime: int = 86400) -> bool:
    """
    Create a bounty timestamp if one doesn't already exist.
    """
    # Check if chute is disabled before creating bounty
    if await is_chute_disabled(chute_id):
        logger.info(f"Bounty creation blocked for disabled chute {chute_id}")
        return False

    # Rate limit bounty creation to prevent race conditions where a bounty is
    # consumed while an instance check loop is running, triggering a new bounty
    # even though there are now hot instances.
    cooldown_key = f"bounty_cooldown:{chute_id}"
    try:
        cooldown_active = await settings.lite_redis_client.exists(cooldown_key)
        if cooldown_active:
            return False
    except Exception as exc:
        logger.warning(f"Failed to check bounty cooldown: {exc}")

    key = _bounty_key(chute_id)
    data = str(datetime.now(timezone.utc).timestamp())
    try:
        result = await settings.lite_redis_client.eval(
            CREATE_BOUNTY_LUA,
            1,
            key,
            data,
            lifetime,
        )
        if result:
            # Set cooldown to prevent rapid bounty recreation
            await settings.lite_redis_client.set(
                cooldown_key, "1", ex=BOUNTY_COOLDOWN_SECONDS
            )
            # Record the demand signal (a newly created bounty means the chute is wanted hot).
            # The bounty's creation timestamp (stored above) is the request->hot start time, read
            # back at activation via claim_bounty()'s age_seconds.
            track_warmup_request(chute_id, WarmupTrigger.BOUNTY)
        return bool(result)
    except Exception as exc:
        logger.warning(f"Failed to create bounty: {exc}")
    return False


async def claim_bounty(
    chute_id: str,
    *,
    attempt_id: Optional[str] = None,
) -> Optional[dict]:
    """
    Atomically claim a bounty. Returns dict with bounty info including age for boost calculation.
    Also sets the cooldown to prevent immediate bounty recreation.

    Activation callers must supply their persisted attempt ID. In that mode the
    Lua operation records and replays an exact result envelope, including the
    no-bounty result, so a lost Redis response cannot consume authority twice.
    """
    key = _bounty_key(chute_id)
    if attempt_id is not None:
        data = await settings.lite_redis_client.eval(
            CLAIM_BOUNTY_REPLAY_LUA,
            3,
            key,
            _activation_bounty_replay_key(attempt_id),
            f"bounty_cooldown:{chute_id}",
            attempt_id,
            ACTIVATION_REPLAY_TTL_SECONDS,
            BOUNTY_COOLDOWN_SECONDS,
            chute_id,
        )
        return _parse_activation_claim_envelope(data, attempt_id, chute_id)

    try:
        data = await settings.lite_redis_client.eval(
            CLAIM_BOUNTY_LUA,
            1,
            key,
        )
        if not data:
            return None

        # Set cooldown immediately after consuming bounty to prevent race conditions
        # where a new bounty gets created while instances are still spinning up
        cooldown_key = f"bounty_cooldown:{chute_id}"
        try:
            await settings.lite_redis_client.set(
                cooldown_key, "1", ex=BOUNTY_COOLDOWN_SECONDS
            )
            # Extra delete in case there was a brief race condition
            await settings.lite_redis_client.delete(key)
        except Exception as exc:
            logger.warning(f"Failed to set bounty cooldown after claim: {exc}")

        created_at = _parse_timestamp(data)
        if created_at is None:
            return None
        age_seconds = int(time.time() - created_at)
        bounty_amount = min(3 * age_seconds + 100, 86400)
        return {
            "amount": bounty_amount,
            "created_at": created_at,
            "age_seconds": age_seconds,
        }
    except Exception as exc:
        logger.warning(f"Failed to claim bounty: {exc}")
    return None


def calculate_bounty_boost(age_seconds: int) -> float:
    """
    Calculate compute multiplier boost based on bounty age.

    The boost ramps up from BOUNTY_BOOST_MIN (1.1x) to BOUNTY_BOOST_MAX (1.5x)
    over BOUNTY_BOOST_RAMP_MINUTES (180 minutes).

    This incentivizes miners to respond to older/more urgent bounties.
    """
    age_minutes = age_seconds / 60.0

    if age_minutes <= 0:
        return BOUNTY_BOOST_MIN
    elif age_minutes >= BOUNTY_BOOST_RAMP_MINUTES:
        return BOUNTY_BOOST_MAX
    else:
        # Linear ramp from min to max
        t = age_minutes / BOUNTY_BOOST_RAMP_MINUTES
        return BOUNTY_BOOST_MIN + t * (BOUNTY_BOOST_MAX - BOUNTY_BOOST_MIN)


async def get_bounty_info(chute_id: str) -> Optional[dict]:
    """
    Get full bounty info for a chute without claiming it.

    Returns dict with:
    - amount: bounty amount (based on age)
    - boost: dynamic boost multiplier (1.5x at 0min -> 4x at 180min+)
    - age_seconds: how old the bounty is
    - created_at: timestamp when bounty was created

    Returns None if no bounty exists.
    """
    key = _bounty_key(chute_id)
    try:
        data = await settings.lite_redis_client.get(key)
        if not data:
            return None
        created_at = _parse_timestamp(data)
        if created_at is None:
            return None
        age_seconds = int(time.time() - created_at)
        bounty_amount = min(3 * age_seconds + 100, 86400)
        return {
            "amount": bounty_amount,
            "boost": calculate_bounty_boost(age_seconds),
            "age_seconds": age_seconds,
            "created_at": created_at,
        }
    except Exception as exc:
        logger.warning(f"Failed to get bounty info: {exc}")
    return None


async def get_bounty_boost(chute_id: str) -> float:
    """
    Get the current bounty boost for a chute without claiming it.
    Returns the dynamic boost based on bounty age, or 1.0 if no bounty exists.
    """
    info = await get_bounty_info(chute_id)
    return info["boost"] if info else 1.0


async def check_bounty_exists(chute_id: str) -> bool:
    """
    Check if a bounty exists without claiming it.
    """
    key = _bounty_key(chute_id)
    try:
        exists = await settings.lite_redis_client.exists(key)
        return bool(exists)
    except Exception as exc:
        logger.warning(f"Failed to check bounty existence: {exc}")
    return False


async def get_bounty_amount(chute_id: str) -> Optional[int]:
    """
    Get bounty amount without claiming it.
    """
    info = await get_bounty_info(chute_id)
    return info["amount"] if info else None


async def get_bounty_amounts(chute_ids: list[str]) -> dict[str, int]:
    """
    Fetch bounty amounts for multiple chutes in a single Redis round-trip.
    """
    if not chute_ids:
        return {}

    keys = [_bounty_key(chute_id) for chute_id in chute_ids]
    results: dict[str, int] = {}
    try:
        values = await settings.lite_redis_client.mget(*keys)
        for chute_id, data in zip(chute_ids, values):
            if not data:
                continue
            created_at = _parse_timestamp(data)
            if created_at is None:
                continue
            age_seconds = int(time.time() - created_at)
            results[chute_id] = min(3 * age_seconds + 100, 86400)
    except Exception as exc:
        logger.warning(f"Failed to get bounty amounts: {exc}")
    return results


async def get_bounty_infos(chute_ids: list[str]) -> dict[str, dict]:
    """
    Fetch bounty info for multiple chutes in a single Redis round-trip.
    Returns a mapping of chute_id -> bounty info dict.
    """
    if not chute_ids:
        return {}

    keys = [_bounty_key(chute_id) for chute_id in chute_ids]
    results: dict[str, dict] = {}
    try:
        values = await settings.lite_redis_client.mget(*keys)
        for chute_id, data in zip(chute_ids, values):
            if not data:
                continue
            created_at = _parse_timestamp(data)
            if created_at is None:
                continue
            age_seconds = int(time.time() - created_at)
            results[chute_id] = {
                "amount": min(3 * age_seconds + 100, 86400),
                "boost": calculate_bounty_boost(age_seconds),
                "age_seconds": age_seconds,
                "created_at": created_at,
            }
    except Exception as exc:
        logger.warning(f"Failed to get bounty infos: {exc}")
    return results


async def delete_bounty(chute_id: str) -> bool:
    """
    Manually delete a bounty.
    """
    key = _bounty_key(chute_id)
    try:
        result = await settings.lite_redis_client.delete(key)
        return bool(result)
    except Exception as exc:
        logger.warning(f"Failed to delete bounty: {exc}")
    return False


async def send_bounty_notification(
    chute_id: str,
    bounty: int,
    effective_multiplier: Optional[float] = None,
    bounty_boost: Optional[float] = None,
    urgency: Optional[str] = None,
) -> None:
    """
    Send bounty notification to miners.

    Args:
        chute_id: The chute ID
        bounty: Bounty amount
        effective_multiplier: Total effective compute multiplier for this chute
        bounty_boost: Current dynamic bounty boost (1.1x-1.5x based on age)
        urgency: Optional urgency level ("cold", "scaling", "critical")
    """
    try:
        data = {
            "chute_id": chute_id,
            "bounty": bounty,
        }
        if effective_multiplier is not None:
            data["effective_multiplier"] = effective_multiplier
        if bounty_boost is not None:
            data["bounty_boost"] = bounty_boost
        if urgency is not None:
            data["urgency"] = urgency

        await settings.lite_redis_client.publish(
            "miner_broadcast",
            json.dumps({"reason": "bounty_change", "data": data}),
        )

        urgency_str = f" ({urgency})" if urgency else ""
        multiplier_str = ""
        if effective_multiplier is not None:
            multiplier_str = f", {effective_multiplier:.1f}x multiplier"
        await settings.lite_redis_client.publish(
            "events",
            json.dumps(
                {
                    "reason": "bounty_change",
                    "message": f"Chute {chute_id} bounty{urgency_str}: {bounty} compute units{multiplier_str}",
                    "data": data,
                }
            ),
        )
    except Exception as exc:
        logger.error(f"Failed to send bounty notification: {exc}")


async def list_bounties() -> list[dict]:
    """
    List all available bounties with their current amounts.
    """
    bounties = []
    try:
        cursor = 0
        pattern = f"{BOUNTY_KEY_PREFIX}*"
        while True:
            cursor, keys = await settings.lite_redis_client.client.scan(
                cursor, match=pattern, count=1000
            )
            for key in keys:
                try:
                    data = await settings.lite_redis_client.get(key)
                    if not data:
                        continue
                    created_at = _parse_timestamp(data)
                    if created_at is None:
                        continue
                    # Extract chute_id from key
                    if isinstance(key, bytes):
                        key = key.decode()
                    chute_id = key[len(BOUNTY_KEY_PREFIX) :]
                    age_seconds = int(time.time() - created_at)
                    ttl = await settings.lite_redis_client.ttl(key)
                    bounties.append(
                        {
                            "chute_id": chute_id,
                            "bounty_amount": min(3 * age_seconds + 100, 86400),
                            "seconds_elapsed": age_seconds,
                            "time_remaining": ttl if ttl > 0 else 0,
                            "created_at": created_at,
                        }
                    )
                except Exception as exc:
                    logger.warning(f"Failed to parse bounty data for key {key}: {exc}")
                    continue
            if cursor == 0:
                break
        bounties.sort(key=lambda x: x["created_at"])
    except Exception as exc:
        logger.error(f"Failed to list bounties: {exc}")
    return bounties
