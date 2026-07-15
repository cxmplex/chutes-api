"""Deterministic, structurally valid TDX quote-v4 parser fixture.

This is synthetic parser evidence, not a hardware quote and not DCAP-signature-valid. Live
hardware/DCAP validation requires a genuine platform quote and collateral.
"""

import struct

EXPECTED_MRTD = (
    "DDC6EFCDD2309E10837F8A7F64B71272B7EF003B129460410FE715BDFFFEC38C7"
    "C0C1686DDDB2A23D4FD623D145E8455"
)
EXPECTED_RTMR0 = (
    "F57DDE95EE98C7F7AE1284A5782FF5029D8FF25AD113467C1E8088EE5E3C65B3"
    "CE8FF15BA46F329D9B085C55D171D73A"
)
EXPECTED_RTMR1 = (
    "D20EB28CA35D29857D00DFE8875063F10900AAE31CF23C2CDB0F7091A0E89358"
    "C8569EDD55DDD596B78C515441422925"
)
EXPECTED_RTMR2 = (
    "95521B8702C3E2B43D9A938653762FE4A86A65BCF31B58C2821BC339E56EF806"
    "CCD44A26C9D6DB3992EF3060BEB416B3"
)
EXPECTED_RTMR3 = "0" * 96
EXPECTED_REPORT_DATA = (
    "6162636431323334000000000000000000000000000000000000000000000000"
    "0000000000000000000000000000000000000000000000000000000000000000"
)


def build_synthetic_tdx_v4_quote() -> bytes:
    signature = bytes(range(64))
    quote = bytearray(636 + len(signature))
    struct.pack_into(
        "<HHI16s20s",
        quote,
        0,
        4,
        2,
        0x81,
        bytes.fromhex("939A7233F79C4CA9940A0DB3957F0607"),
        bytes.fromhex("00112233445566778899AABBCCDDEEFF01020304"),
    )
    report_offset = 48
    quote[report_offset + 136 : report_offset + 184] = bytes.fromhex(EXPECTED_MRTD)
    quote[report_offset + 328 : report_offset + 376] = bytes.fromhex(EXPECTED_RTMR0)
    quote[report_offset + 376 : report_offset + 424] = bytes.fromhex(EXPECTED_RTMR1)
    quote[report_offset + 424 : report_offset + 472] = bytes.fromhex(EXPECTED_RTMR2)
    quote[report_offset + 472 : report_offset + 520] = bytes.fromhex(EXPECTED_RTMR3)
    quote[report_offset + 520 : report_offset + 584] = bytes.fromhex(EXPECTED_REPORT_DATA)
    struct.pack_into("<I", quote, 632, len(signature))
    quote[636:] = signature
    return bytes(quote)


SYNTHETIC_TDX_V4_QUOTE = build_synthetic_tdx_v4_quote()
