import inspect
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

import pytest
from fastapi.responses import StreamingResponse

from api.instance.router import stream_logs


class _Result:
    def __init__(self, instance):
        self.instance = instance

    def unique(self):
        return self

    def scalar_one_or_none(self):
        return self.instance


class _SessionContext:
    def __init__(self, instance):
        self.session = SimpleNamespace(execute=AsyncMock(return_value=_Result(instance)))
        self.exited = False

    async def __aenter__(self):
        return self.session

    async def __aexit__(self, *_args):
        self.exited = True


@pytest.mark.asyncio
async def test_log_stream_closes_database_session_before_returning_response():
    chute = SimpleNamespace(user_id="owner", chute_id="chute-1", public=False)
    instance = SimpleNamespace(
        chute=chute,
        host="192.0.2.10",
        miner_hotkey="miner",
        port_mappings=[{"internal_port": 8001, "external_port": 31001}],
    )
    session_context = _SessionContext(instance)
    current_user = SimpleNamespace(user_id="owner", has_role=lambda _role: False)

    with patch("api.instance.router.get_session", return_value=session_context):
        response = await stream_logs(
            "instance-1",
            request=SimpleNamespace(),
            backfill=100,
            hotkey=None,
            current_user=current_user,
        )

    assert isinstance(response, StreamingResponse)
    assert session_context.exited is True
    assert "db" not in inspect.signature(stream_logs).parameters
