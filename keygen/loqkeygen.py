#!/usr/bin/env python3
"""loqkeygen — Loquendo TTS 7 license generator.

Generates a Windows .reg file (and/or prints the values) that licenses the
original Loquendo TTS 7 engine for a given machine MAC address and username.
Everything is derived locally: Code (DES-variant cipher + CRC), Abil (GP6
base62), and the plain registry values, exactly as Patch.exe produced them.

  ./loqkeygen.py --mac 7A:8B:9C:1D:2E:3F --user wineuser [-o license.reg]
                 [--expiry 20271231 | --permanent] [--dry-run]

Default expiry is permanent ("99999999"). The license is bound to the MAC;
run the engine inside a network namespace holding a dummy network card with
that address (pattern shown in README.md).

Clean-room reimplementation for historical preservation of abandonware.
"""
import argparse
import datetime
import os
import sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from loqkey import encrypt_code, make_abil, make_payload  # noqa: E402


def format_expiry(spec):
    if spec == "permanent":
        return "99999999"
    try:
        d = datetime.date.fromisoformat(spec)
    except ValueError:
        d = datetime.datetime.strptime(spec, "%Y%m%d").date()
    return d.strftime("%Y%m%d")


def reg_dquote(s):
    return s.replace("\\", "\\\\").replace('"', '\\"')


def build_reg(mac, user, expiry):
    values = {
        "Abil": make_abil(mac, user),
        "Channels": "256",
        "Code": encrypt_code(make_payload(user, make_abil(mac, user), expiry)),
        "Code2": "",
        "Code3": "",
        "Name": user if len(user) >= 7 else user + "+" * (7 - len(user)),
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


def main():
    ap = argparse.ArgumentParser(description="Loquendo TTS 7 license keygen")
    ap.add_argument("--mac", required=True, help='MAC address, e.g. "7A:8B:9C:1D:2E:3F"')
    ap.add_argument("--user", required=True, help="licensed username (Windows login name)")
    ap.add_argument("--expiry", default="permanent",
                    help='"permanent", YYYY-MM-DD or YYYYMMDD (default: permanent)')
    ap.add_argument("-o", "--output", help="write .reg file here (default: print)")
    ap.add_argument("--dry-run", action="store_true", help="print values, skip .reg output")
    args = ap.parse_args()

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
    print("expiry     %s" % ("permanent" if expiry == "99999999" else expiry))
    if args.dry_run:
        return
    if args.output:
        with open(args.output, "w", newline="") as f:
            f.write(reg)
        print("wrote", args.output)


if __name__ == "__main__":
    main()
