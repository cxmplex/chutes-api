import gc
import asyncio
import traceback
import httpx as _httpx
import api.database.orms  # noqa
from loguru import logger
from api.config import settings
from sqlalchemy import select, text
from api.util import notify_deleted
from api.database import get_session
import api.miner_client as miner_client
from api.instance.schemas import Instance
from api.instance.util import invalidate_instance_cache


async def check_instance_logging_server(instance: Instance) -> bool:
    """
    Check a single instance's logging server.
    """
    logger.info(
        f"Checking {instance.instance_id=} of {instance.miner_hotkey=} {instance.chute_id=}"
    )
    log_port = None
    try:
        log_port = next(p for p in instance.port_mappings if p["internal_port"] == 8001)[
            "external_port"
        ]

        # TEE instances serve the logging port over TLS with the attested cert (the logging port is
        # DNAT'd through the untrusted host), so pin the probe to that cert (CN->IP). Without this,
        # the plaintext probe would always fail post-TLS and the 3-strikes rule would delete every
        # TEE instance. Non-TEE instances keep the plain-http probe.
        if instance.cacert:
            from api.instance.connection import build_pinned_client

            client = build_pinned_client(
                instance.cacert, instance.host, log_port, read_timeout=10.0
            )
        else:
            client = _httpx.AsyncClient(
                base_url=f"http://{instance.host}:{log_port}",
                timeout=_httpx.Timeout(connect=10.0, read=10.0, write=10.0, pool=10.0),
            )

        try:
            headers, _ = miner_client.sign_request(instance.miner_hotkey, purpose="chutes")
            resp = await client.get("/logs", headers=headers)
            resp.raise_for_status()
            json_data = resp.json()
            if "logs" not in json_data:
                raise ValueError("Missing 'logs' key in response")
            has_required_log = any(
                log.get("path") == "/tmp/_chute.log" for log in json_data["logs"]
            )
            if not has_required_log:
                raise ValueError("No log entry with path '/tmp/_chute.log' found")
            proto = "https" if instance.cacert else "http"
            logger.success(
                f"✅ logging server running for {instance.instance_id=} of {instance.miner_hotkey=} for {instance.chute_id=} on {proto}://{instance.host}:{log_port}"
            )
            return True
        finally:
            await client.aclose()
    except Exception as exc:
        proto = "https" if instance.cacert else "http"
        logger.error(
            f"❌ logging server check failure for {instance.instance_id=} of {instance.miner_hotkey=} for {instance.chute_id=} on {proto}://{instance.host}:{log_port or '???'}: {str(exc)}\n{traceback.format_exc()}"
        )
        return False


async def handle_check_result(instance_id: str, success: bool):
    """
    Handle the result of a check by updating Redis failure tracking.
    """
    redis_key = f"logserverfail:{instance_id}"
    if success:
        await settings.redis_client.delete(redis_key)
        return
    failure_count = await settings.redis_client.incr(redis_key)
    await settings.redis_client.expire(redis_key, 600)
    if failure_count >= 3:
        async with get_session() as session:
            instance = (
                (await session.execute(select(Instance).where(Instance.instance_id == instance_id)))
                .unique()
                .scalar_one_or_none()
            )
            if instance:
                logger.error(
                    f"❌ max consecutive logging server check failures encountered for {instance.instance_id=} of {instance.miner_hotkey=} for {instance.chute_id=}"
                )
                await session.delete(instance)
                await session.execute(
                    text(
                        "UPDATE instance_audit SET deletion_reason = 'Failed 3 or more consecutive logging server probes.' WHERE instance_id = :instance_id"
                    ),
                    {"instance_id": instance.instance_id},
                )
                await notify_deleted(
                    instance, message="Failed 3 or more consecutive logging server probes."
                )
                await invalidate_instance_cache(instance.chute_id, instance_id=instance.instance_id)
                await session.commit()


async def check_logging_servers(max_concurrent: int = 32):
    """
    Check all active instances' logging servers with concurrent execution.
    """
    semaphore = asyncio.Semaphore(max_concurrent)

    async def check_with_semaphore(instance: Instance):
        async with semaphore:
            success = await check_instance_logging_server(instance)
            await handle_check_result(instance.instance_id, success)
            return instance.instance_id, success

    async with get_session() as session:
        query = select(Instance).where(Instance.active.is_(True))
        result = await session.stream(query)
        instances = []
        async for row in result.unique():
            instances.append(row[0])
        logger.info(f"Checking {len(instances)} active instances")
        tasks = [check_with_semaphore(instance) for instance in instances]
        results = await asyncio.gather(*tasks)
        successful = sum(1 for _, success in results if success)
        failed = len(results) - successful
        logger.success("=" * 80)
        logger.success(f"Check complete: {successful} successful, {failed} failed")
        if failed > 0:
            failed_ids = [instance_id for instance_id, success in results if not success]
            logger.warning(f"Failed instances: {failed_ids}")


if __name__ == "__main__":
    gc.set_threshold(5000, 50, 50)
    asyncio.run(check_logging_servers())
