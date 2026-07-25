from datetime import datetime, timezone
from unittest.mock import AsyncMock, Mock

import pytest

from api.registry import router as registry_router


@pytest.mark.asyncio
async def test_deleted_launch_config_is_not_a_registry_lifecycle():
    server = Mock(
        server_id="gpu-server",
        miner_hotkey="owner",
        gpu_launch_reservation_id="reservation",
    )
    config = Mock(
        server_id=server.server_id,
        miner_hotkey=server.miner_hotkey,
        gpu_management_mode="miner",
        gpu_launch_reservation_id=server.gpu_launch_reservation_id,
        failed_at=None,
        verification_error=None,
        registry_scope_active=False,
        registry_scope_revoked_at=datetime.now(timezone.utc),
    )
    assert not await registry_router._miner_launch_scope_current(
        AsyncMock(),
        server,
        config,
    )
