# loquendo-keygen

Keygen and full reverse-engineering notes for **Loquendo TTS 7**'s "UNIFIED
Licensing SW", written for historical preservation. Loquendo TTS 7 is long-dead
abandonware — licenses have not been purchasable for years. This project lets
preservationists run the original engine anywhere (any host, any MAC), and
documents the licensing scheme completely.

It also supports reimplementation projects (like quoquendo), which hook the
original engine as a reference oracle.

## Layout

| Path | Content |
|---|---|
| `src/loqkeygen/` | the keygen package — pure-Python stdlib-only implementation, installable via `uv`/pip |
| `research/loqemu.py` | Unicorn-based emulation harness used as an oracle against the original `LoqTTS7.dll` during reverse engineering (needs the original DLL, not distributed here) |
| `RESEARCH.md` | complete reverse-engineering notes: cipher, key schedule, payload slots, Abil derivation, engine validation path, expiry semantics |
| `work/` | gitignored: original engine binaries, Wine prefix, activation tools used as research inputs |

## Usage

No runtime dependencies (Python ≥ 3.9, stdlib only). With [uv](https://docs.astral.sh/uv/):

```sh
uv run loqkeygen --mac 52:54:00:12:34:56 --user keygen-test -o license.reg
wine reg import license.reg     # into your engine's Wine prefix
```

Or, as a plain install (any pip-capable environment):

```sh
pip install .
loqkeygen --mac 52:54:00:12:34:56 --user keygen-test -o license.reg
```

As a library: `from loqkeygen import make_abil, encrypt_code, make_payload`.

Values written under
`HKLM\Software\Wow6432Node\Loquendo\LTTS7\LicenseCode`:
`Code`, `Abil`, `Channels="256"`, `TTSVersion="7"`, `Name`, empty
`Code2`/`Code3`/`PIK`. `--expiry 2027-12-31` (or `YYYYMMDD`) instead of the
default permanent license.

The engine additionally needs
`HKLM\...\Loquendo\LTTS7\default.session\DataPath` pointing at the engine's
`Data\` directory (plain string, no crypto — see the "E2E verification"
section of RESEARCH.md).

The license is bound to the MAC and username. Run the engine inside a network
namespace with a dummy interface carrying the licensed MAC:

```sh
unshare -rn sh -c 'ip link add dummy0 type dummy &&
  ip link set dev dummy0 address 52:54:00:12:34:56 && ip link set dummy0 up &&
  wine ...'
```

Usernames shorter than 7 characters are `'+'`-padded to 7 (matching the
original tool); the padded name is what must match the Windows login name.

## Verification

- Crypto: `uv run pytest` — regenerates the known-good Code
  (`MAC 7A:8B:9C:1D:2E:3F`, user `wineuser`) byte-for-byte, plus 200 random
  round-trips.
- End-to-end: a license for a *fresh* MAC/user (`52:54:00:12:34:56`,
  `keygen-test`) was imported into a Wine prefix with the original engine; the
  engine synthesized 2.73 s of Italian audio ("Ciao dal keygen, questo è un
  test") under the dummy-MAC harness. Details in RESEARCH.md.

## Legal

Provided for historical research and preservation of abandoned software. The
Loquendo TTS product line is discontinued; no licenses are sold. Do not use
this against software you could legitimately license.
