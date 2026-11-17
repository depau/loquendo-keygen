"""Tests for the loqkeygen crypto core: known-good tuple + round-trips.

Known-good license (MAC 7A:8B:9C:1D:2E:3F, user "wineuser") produced by the
original Patch.exe tooling; the keygen must reproduce it byte-for-byte.
"""

import random


from loqkeygen import (decrypt_code, encrypt_code, make_abil,  # noqa: F401
                       make_name_field, make_payload)
from loqkeygen.cli import build_reg, format_expiry

KNOWN_CODE = ("D2FCEFB9875BAF17AF2242B47077E3191219A72AFDBC3CFF8CD68C8811FEEE0B"
              "6D489E482514244C13B4313D3148F1C355B63A52A652761292A3CDCED759D77A"
              "E77BBA3DECA1D9A100001556")
KNOWN_MAC = "7A:8B:9C:1D:2E:3F"
KNOWN_USER = "wineuser"
KNOWN_ABIL = "IT192MU2NQk0YIa6"


def test_known_good_abil():
    assert make_abil(KNOWN_MAC, KNOWN_USER) == KNOWN_ABIL


def test_known_good_code():
    abil = make_abil(KNOWN_MAC, KNOWN_USER)
    code = encrypt_code(make_payload(KNOWN_USER, abil))
    assert code == KNOWN_CODE


def test_known_good_decrypt():
    pt = decrypt_code(KNOWN_CODE)
    assert pt == make_payload(KNOWN_USER, KNOWN_ABIL)


def test_round_trips():
    rng = random.Random(7)
    for _ in range(200):
        payload = rng.randbytes(72)
        assert decrypt_code(encrypt_code(payload)) == payload


def test_expiry_permanent_sentinel():
    # "99999999" is the permanent-license sentinel; it must encode to itself
    assert format_expiry("permanent") == "99999999"
    pt = make_payload(KNOWN_USER, KNOWN_ABIL)
    assert pt[16:24] == b"99999999"


def test_expiry_date_formats():
    assert format_expiry("2027-12-31") == "20271231"
    assert format_expiry("20271231") == "20271231"
    pt = make_payload(KNOWN_USER, KNOWN_ABIL, "20301117")
    assert pt[16:24] == b"20301117"


def test_name_field_cyclic_layout():
    field = make_name_field("wineuser")
    assert len(field) == 32
    # stride 9 (len+1), NUL-terminated copies, byte 31 forced to 0
    assert field[:9] == b"wineuser\x00"
    assert field[9:18] == b"wineuser\x00"
    assert field[18:27] == b"wineuser\x00"
    assert field[27] == ord("w")
    assert field[31] == 0


def test_plus_padding_matches_name_value():
    # usernames <7 chars are '+'-padded to 7, and that padded name is what
    # lands in the payload (and must match the Windows login name)
    pt = make_payload("keygen-test", make_abil("52:54:00:12:34:56", "keygen-test"))
    assert pt.startswith(b"keygen-test\x00")
    pt_short = make_payload("abcd", make_abil("52:54:00:12:34:56", "abcd+++"))
    assert pt_short.startswith(b"abcd+++\x00")


def test_abil_carries_name_and_mac():
    assert make_abil("52:54:00:12:34:56", KNOWN_USER) != KNOWN_ABIL
    assert make_abil(KNOWN_MAC, "otheruser") != KNOWN_ABIL


def test_build_reg_values():
    values, reg = build_reg(KNOWN_MAC, KNOWN_USER)
    assert values["Code"] == KNOWN_CODE
    assert values["Abil"] == KNOWN_ABIL
    assert values["Name"] == KNOWN_USER
    assert values["Channels"] == "256"
    assert values["TTSVersion"] == "7"
    assert reg.startswith("Windows Registry Editor Version 5.00\r\n")
    assert "[HKEY_LOCAL_MACHINE\\Software\\Wow6432Node\\Loquendo\\LTTS7\\LicenseCode]" in reg
    for empty in ("Code2", "Code3", "PIK"):
        assert values[empty] == ""


def test_pad_name_propagates_to_whole_chain():
    # Patch.exe pads the username once, before the whole chain: interleave,
    # payload name field, and registry Name all see the padded name
    from loqkeygen import pad_name
    mac = "52:54:00:12:34:56"
    assert pad_name("abcd") == "abcd+++"
    assert pad_name("abcdefg") == "abcdefg"
    assert make_abil(mac, "abcd") == make_abil(mac, "abcd+++")
    pt = make_payload("abcd", make_abil(mac, "abcd"))
    assert pt.startswith(b"abcd+++\x00")
