"""CLI: generate a Loquendo TTS 7 license (.reg file) for a MAC + username.

  loqkeygen --mac 7A:8B:9C:1D:2E:3F --user wineuser [-o license.reg]
            [--expiry 2027-12-31 | --permanent] [--dry-run]

Default expiry is permanent ("99999999"). The license is bound to the MAC;
run the engine inside a network namespace holding a dummy network card with
that address (pattern shown in README.md).

Clean-room reimplementation for historical preservation of abandonware.
"""

import argparse
import datetime
import sys

from .core import encrypt_code, make_abil, make_payload, pad_name

_EXPIRY_PERMANENT = "99999999"


def format_expiry(spec):
    if spec == "permanent":
        return _EXPIRY_PERMANENT
    try:
        d = datetime.date.fromisoformat(spec)
    except ValueError:
        d = datetime.datetime.strptime(spec, "%Y%m%d").date()
    return d.strftime("%Y%m%d")


def reg_dquote(s):
    return s.replace("\\", "\\\\").replace('"', '\\"')


def build_reg(mac, user, expiry=_EXPIRY_PERMANENT):
    abil = make_abil(mac, user)
    values = {
        "Abil": abil,
        "Channels": "256",
        "Code": encrypt_code(make_payload(user, abil, expiry)),
        "Code2": "",
        "Code3": "",
        "Name": pad_name(user),
        "PIK": "",
        "TTSVersion": "7",
    }
    lines = [
        "Windows Registry Editor Version 5.00",
        "",
        "[HKEY_LOCAL_MACHINE\\Software\\Wow6432Node\\Loquendo\\LTTS7\\LicenseCode]",
        "",
    ]
    for k in sorted(values):
        lines.append('"%s"="%s"' % (k, reg_dquote(values[k])))
        lines.append("")
    return values, "\r\n".join(lines)


def main(argv=None):
    ap = argparse.ArgumentParser(
        prog="loqkeygen", description="Loquendo TTS 7 license keygen")
    ap.add_argument("--mac", required=True,
                    help='MAC address, e.g. "7A:8B:9C:1D:2E:3F"')
    ap.add_argument("--user", required=True,
                    help="licensed username (Windows login name)")
    ap.add_argument("--expiry", default="permanent",
                    help='"permanent", YYYY-MM-DD or YYYYMMDD (default: permanent)')
    ap.add_argument("-o", "--output", help="write .reg file here (default: print)")
    ap.add_argument("--dry-run", action="store_true",
                    help="print values, skip .reg output")
    args = ap.parse_args(argv)

    mac = args.mac.strip().upper()
    if len(mac) != 17 or mac[2] != ":":
        ap.error("--mac must look like 7A:8B:9C:1D:2E:3F")
    user = args.user
    if not user or len(user) > 32 or any(c in user for c in '"\\\r\n\0'):
        ap.error("--user: 1-32 chars, no quotes/backslashes")

    expiry = format_expiry(args.expiry)
    values, reg = build_reg(mac, user, expiry)

    for k in sorted(values):
        print("%-10s %s" % (k, values[k]))
    print("expiry     %s" % ("permanent" if expiry == _EXPIRY_PERMANENT else expiry))
    if args.dry_run:
        return 0
    if args.output:
        with open(args.output, "w", newline="") as f:
            f.write(reg)
        print("wrote", args.output)
    return 0


if __name__ == "__main__":
    sys.exit(main())
