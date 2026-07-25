from types import SimpleNamespace

import pytest
from fastapi import HTTPException
from unittest.mock import AsyncMock, patch

from api.node.router import require_generic_node_deletion
from api.server.service import delete_server


def test_generic_deletion_rejects_reservation_owned_gpu_node():
    node = SimpleNamespace(
        gpu_allocation_group_id="group-1",
        gpu_allocation_group_generation=1,
    )
    with pytest.raises(HTTPException) as exc:
        require_generic_node_deletion(node)
    assert exc.value.status_code == 409
    assert "teardown/reset" in exc.value.detail


def test_generic_deletion_allows_legacy_unallocated_node():
    require_generic_node_deletion(SimpleNamespace(gpu_allocation_group_id=None))


@pytest.mark.asyncio
async def test_generic_server_deletion_rejects_reservation_owned_gpu():
    server = SimpleNamespace(
        compute_type="gpu",
        gpu_launch_reservation_id="reservation",
    )
    with (
        patch(
            "api.server.service.check_server_ownership",
            AsyncMock(return_value=server),
        ),
        pytest.raises(HTTPException) as exc,
    ):
        await delete_server(AsyncMock(), "gpu-server", "owner")
    assert exc.value.status_code == 409
    assert "teardown/reset" in exc.value.detail
