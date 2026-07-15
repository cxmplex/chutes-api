import base64

import pytest

from tests.fixtures.tdx_synthetic import (
    EXPECTED_MRTD as _EXPECTED_MRTD,
    EXPECTED_REPORT_DATA,
    EXPECTED_RTMR0 as _EXPECTED_RTMR0,
    EXPECTED_RTMR1 as _EXPECTED_RTMR1,
    EXPECTED_RTMR2 as _EXPECTED_RTMR2,
    EXPECTED_RTMR3 as _EXPECTED_RTMR3,
    SYNTHETIC_TDX_V4_QUOTE,
)

EXPECTED_MRTD = _EXPECTED_MRTD
EXPECTED_RMTR0 = _EXPECTED_RTMR0
EXPECTED_RMTR1 = _EXPECTED_RTMR1
EXPECTED_RMTR2 = _EXPECTED_RTMR2
EXPECTED_RMTR3 = _EXPECTED_RTMR3
EXPECTED_USER_DATA = EXPECTED_REPORT_DATA

TDX_BOOT_RMTRS = (
    f"rtmr0={EXPECTED_RMTR0},rtmr1={EXPECTED_RMTR1},rtmr2={EXPECTED_RMTR2},rtmr3={EXPECTED_RMTR3}"
)
TDX_RUNTIME_RMTRS = (
    f"rtmr0={EXPECTED_RMTR0},rtmr1={EXPECTED_RMTR1},rtmr2={EXPECTED_RMTR2},rtmr3={EXPECTED_RMTR3}"
)


@pytest.fixture
def valid_quote_base64():
    """Return the deterministic structural v4 fixture (not hardware/DCAP evidence)."""
    return base64.b64encode(SYNTHETIC_TDX_V4_QUOTE).decode("utf-8")


@pytest.fixture
def valid_quote_bytes(valid_quote_base64):
    """Return the decoded bytes of the valid quote."""
    return base64.b64decode(valid_quote_base64)
