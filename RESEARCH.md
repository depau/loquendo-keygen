# Loquendo LTTS7 "UNIFIED Licensing SW" — Reverse Engineering Notes

Working notes, evidence-first. All algorithms below are re-derived from disassembly
of the original binaries (clean-room: re-written from evidence, never pasted from
a decompiler). Everything here is implemented and self-tested in
`keygen/loqkey.py` (cipher, CRC, payload, Abil derivation) and
`keygen/loqkeygen.py` (license generator). The emulation oracle used to settle
ambiguities during RE is `research/loqemu.py`.

Status: **fully cracked**. The keygen reproduces a shipped known-good license
byte-for-byte, and a freshly generated license (arbitrary MAC + username) drives
the original engine to synthesize speech (E2E verified in a Wine prefix).

## Analyzed binaries

None of these are distributed in this repository; they are original Loquendo /
third-party files used as analysis inputs (paths shown relative to the
gitignored `work/` research directory):

| File | Role |
|---|---|
| `LoqTTS7.dll` (engine `bin/`) | TTS engine, license *validation* (ClaimLicense 0x10003b70, expiry 0x10002bc0, Abil checker 0x10002dd0) |
| `LTTS7LqInt.dll` (engine `bin/`) | MAC enumeration lib ("Unified Licensing SW") |
| `REGVOICE.EXE` (activation tools) | Per-voice activation ("Anastasis Loquendo Voice Activation") |
| `Patch.exe` (community patcher) | Delphi keygen/patcher — *generator* side of the license (image base 0x400000) |

Reference: the known-good license shipped with the community
`loquendo-tts-server` Docker image, registry key

```
Abil     = IT192MU2NQk0YIa6
Channels = 256
Code     = D2FCEFB9875BAF17AF2242B47077E3191219A72AFDBC3CFF8CD68C8811FEEE0B6D489E48
           2514244C13B4313D3148F1C355B63A52A652761292A3CDCED759D77AE77BBA3DECA1D9A1
           00001556                                        (152 chars: 144 hex + 8 CRC hex)
Code2 = ""  Code3 = ""  PIK = ""
Name     = wineuser
TTSVersion = 7
```

Bound host: MAC `7A:8B:9C:1D:2E:3F`, username `wineuser`.
The engine additionally requires `HKLM\...\Loquendo\LTTS7\default.session\DataPath`
= engine `Data\` directory (plain path key, no crypto).

## License `Code` — structure

```
Code = 144 uppercase hex chars (9 blocks × 8 ciphertext bytes, scattered)
     + 8-char uppercase CRC hex (%08X)          → 152 chars total
```

**Scatter** (identical in LoqTTS7.dll and Patch.exe): ciphertext byte j (0..7) of
block k (0..8) is encoded as two hex chars at

```
p = 0x48*i + 0x12*m + 2*k     where (i, m) = divmod(j, 4)
```

i.e. 9 blocks at stride 0x48, 4 byte-pairs per block at stride 0x12, hex pair stride 2.

**CRC** (LTTS7Util `ELQCrcGetChecksum`, Patch.exe FUN_00452184): nibble-table CRC32
(poly 0xEDB88320 reflected), word tables TLO/THI, seed **0x14** for `Code`
(0x13 for `Code2`), computed over the 144 ASCII hex chars (not the raw bytes):
`t=(c^crc)&0xFF; crc = TLO[t&0xF] ^ THI[t>>4] ^ (crc>>8)`. Trailing 8 chars are
`%08X` of the result, written backward (chars 145–152).

## Cipher — DES variant (LoqTTS7.dll 0x100012b0/0x10001360, Patch.exe FUN_00452278)

Hardcoded 8-byte key (both binaries): `07 1E C6 54 B7 01 7E 53`.
Genuine 16-round DES structure (8 iterations × 2 Feistel half-rounds, S-boxes
8×256), but with custom permutation/S-box tables and SWAPMOVE-based IP/FP:

- Round r (r=0..7) uses key dwords `KS[e+3], KS[e+2], KS[e+1], KS[e]` with
  `e = 28 − 4r` — i.e. **consecutive quads walked downward through the 32-dword
  key schedule** (schedule = constant; lifted verbatim as `_KS` in loqkey.py).
- `F(x; kA,kB) = SP[kB^x] | SP[rol(kA^x, 28)]`; each of the two half-rounds per
  iteration is `x ^= F(y)` alternating registers.
- IP/FP are involutions-with-recompute: invert by running the same SWAPMOVE step
  formulas in reverse order; only the final nibble step and IP step5 need special
  algebra (derived and validated in loqkey.py).
- Verification: 200 random round-trips; known-good Code decrypts to a meaningful
  payload; regenerated Code is byte-identical.

## Payload plaintext — 9 slots × 8 bytes

Decrypted from the 144 hex chars (gather + block-decrypt):

| Slot | Bytes | Content (known-good) |
|---|---|---|
| 0,1,3,4 | 32 | **name field**: `name+"\0"` copied at stride len(name)+1, StrLCopy-truncated at 32 bytes, byte 31 NUL — `wineuser\0wineuse…` |
| 2 | 8 | **expiry**: `99999999` = permanent, else `YYYYMMDD` text |
| 5 | 8 | **Abil** first 8 chars — `IT192MU2` |
| 6 | 8 | `FF`×8 (fixed constant) |
| 7 | 8 | **Abil** last 8 chars — `NQk0YIa6` |
| 8 | 8 | `FF`×8 (fixed constant) |

Usernames shorter than 7 chars are padded with `'+'` (0x2B) to exactly 7 chars
(Patch.exe 0x453703) — the padding propagates to the name field, the interleave
input, *and* the registry `Name` value.

## Abil — machine binding (GP6 base62)

Two distinct B62 generators exist, both alphabet
`0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ`:

1. **Generator — Patch.exe FUN_004528c0** (engine-side LoqUpReg has the same shape):
   input is the 44-char MAC/username interleave; output is the 16-char Abil.
   - **Interleave** (FUN_00452a38): dest is a 44-`'_'` template; six groups
     EBP ∈ {1,4,7,10,13,16} write `dest[EBP-1]=MAC[EBP-1]`, `dest[EBP]=MAC[EBP]`
     (MAC indices 0,1,3,4,6,7,9,10,12,13,15,16 — colons skipped), `dest[EBP+1]=user[k]`
     (user chars 0..5); tail copies `user[6:]` to dest[18..43] until its NUL
     (the NUL terminates the string; unfilled tail never reached). Effective
     length = 18 + max(len(user)−6, 0) … capped at 44. MAC = 17-char
     `XX:XX:XX:XX:XX:XX` uppercase-with-colons; user case-sensitive.
     Verified: `interleave("7A:8B:9C:1D:2E:3F", "wineuser") = "7Aw8Bi9Cn1De2Eu3Fser"`.
   - **GP6**: `seed = 0x36`; for i = 0..len−1 (the trailing NUL participates as
     s[len]=0, so the final term is `s[len-1]−1`): `seed *= s[i]+s[i+1]−1`
     (signed 32-bit wrap). `idx0 = |seed % len|` (C signed %).
     `B[0] = T[(s[idx0]*0x13) % 62]`;
     `B[j] = T[(B[j-1]*0x77 + s[(idx0+j−1) % len]) % 62]` for j = 1..15 —
     B[1] **reuses idx0** (no advance), then the index advances once per output
     char. All char values raw ASCII.
     Verified: `gp6("7Aw8Bi9Cn1De2Eu3Fser") == "IT192MU2NQk0YIa6"`.

2. **Engine-side checker — LoqTTS7.dll 0x10002dd0** (a *different* algorithm):
   seed 0xC5, recurrence constants 0x13/0xC5, table @0x10096758 (same alphabet).
   Called from 0x10004000 (`***IGNORE***` handler, input 32 chars) via 0x10002fb0.
   Python port oracle-verified via Unicorn emulation
   (`gen("7Aw8Bi9Cn1De2Eu3") == "Rrhnq7sk40jUILBB"`); see loqkey.py docstring
   history / git for the port.

So **Abil is purely machine+name binding** — it carries no voice/channel info.

## Engine validation path (LoqTTS7.dll)

- **Registry loader** 0x10001160 reads `HKLM\...\Loquendo\LTTS7\LicenseCode`:
  `Code`→[esi+8], `Code2`→[esi+0x208], `Code3`→[esi+0x408], `target`→[esi+0x608].
- **ClaimLicense** 0x10003b70: decodes Code from [arg+0x10]; permanent flag
  [esi+0x1428] set when expiry slot == "99999999"; error state [esi+0x808]
  drives a 7-case jump table @0x10003d54:
  `0=OK, 1=InvalidCode/CRC, 2=unexpected, 3=expired, 5=netadapter-error, 6=host-only`.
  Host-only message uses [esi+0x608] (registry `Target` value).
- **Expiry check** 0x10002bc0: if expiry slot == "99999999" (@0x10096894) →
  permanent. Else GetLocalTime → sprintf `%04d%02d%02d` (fmt @0x100968a0) →
  strcmp(expiry, today): passes when `strcmp <= 0`, i.e. **the license is valid
  the day it encodes and every day before it** — encode `99999999`-style
  permanent instead. Also reads `HKLM\SOFTWARE\Microsoft\SystemID\LocalID`
  (fallback `HKCU\...`) and compares with the same `setle` semantics.
- **Eval entry** 0x10003a00: non-permanent licenses run the expiry check; if
  GetLocalTime year < 0x1999 → fail.

## MAC enumeration (LTTS7LqInt.dll, export `LqInt` @ 0x100025e0)

Dispatcher: guard byte 0xAB @ 0x1000c2c0; name→func table @ 0x1000c2d0:
`MACGetAddress→0x10002270`, `MACGetCount→0x10002300`, +2 more.

Enumeration chain (FUN_10001ea0): `GetAdaptersAddresses` (iphlpapi, IF_TYPES 6/71
only); fallback `Netbios` NCBASTAT per LANA; fallback `GetAdaptersInfo`. Formats
each MAC as `"%02X:%02X:…"` uppercase-with-colons, joins with TAB. DEDST-prefixed
adapters rejected (SNMP path). Output: up to 10 MAC strings + count.

## Patch.exe generator side (FUN_00452ae4 → FUN_004539c8)

Inputs: 17-char MAC from UI combo (SNMP/netbios adapter enumeration), Windows
username (GetUserNameA, `'+'`-padded to 7 when shorter). Produces:

1. `local_10` = interleave(MAC, username) → GP6 → 16-char Abil (`local_14`).
2. `local_0c` = 32-char cyclic username field; `local_18` = `"99999999"`.
3. Nine 8-byte blocks: `[name[0:8], name[8:16], expiry, name[16:24], name[24:32],
   Abil[0:8], FF×8, Abil[8:16], FF×8]`, each DES-encrypted with the hardcoded key
   and hex-scattered into a 153-char `'-'` template.
4. CRC (seed 0x14) over chars 1..144, written backward into 145..152; final Code =
   SubString(1, 152).

Registry writes (`FUN_00453908`, path `SOFTWARE\Loquendo\LTTS7\LicenseCode`, →
Wow6432Node on x64): Code, Code2="", Code3="", PIK="", TTSVersion="7",
Channels="256", Abil (the GP6 string), Name (raw padded username). The tool also
deletes `HKLM/HKCU\SOFTWARE\Microsoft\SystemID` first.

Everything above is re-implemented in `keygen/loqkeygen.py`; the generated
.reg matches Patch.exe's semantics exactly (Code/Abil/Name cross-validated
against the shipped known-good tuple).

## E2E verification (2026-11-17)

Fresh license: MAC `52:54:00:12:34:56`, user `keygen-test` (≠ shipped tuple).
Imported into a private Wine prefix (win64/WoW64) with the original engine
staged in, `default.session\DataPath` added. Ran the engine under `unshare -rn`
with a dummy interface carrying the licensed MAC, voice Roberto, text
"Ciao dal keygen, questo è un test": `ttsNewSession`/`ttsRead` succeeded,
phonetic transcription + event trace written, 2.73 s of 16-bit mono 32 kHz
PCM audio synthesized. The original engine accepts a keygen-generated license
end-to-end.

## Historical side notes

- `Voices` value (e.g. `Allison#Carmen#…#LanguageGuesser`) and `Target`,
  `LicenseTime`, `LicenseExpirationDate` are written by the engine/registration
  flow at runtime, not by Patch.exe; the 9 Patch.exe values suffice for the
  engine to run.
- REGVOICE.EXE / CHKVOICE.DLL ("Anastasis Loquendo Voice Activation") handle
  per-voice activation on top of the engine license; not needed for synthesis.
