"""License crypto core for Loquendo TTS 7's "UNIFIED Licensing SW".

Clean-room port from disassembly of the original binaries (LoqTTS7.dll block
cipher 0x100012b0/0x10001360, key schedule 0x10001570; LTTS7Util.dll
ELQCrcGetChecksum 0x4640; Patch.exe generator side). Validated byte-for-byte
against a known-good shipped license Code, plus 200 random round-trips.

Layout:
  Code  = 144 uppercase hex chars (9 blocks x 8 ciphertext bytes, scattered)
        + 8-char uppercase CRC hex (%08X).
  Scatter: ciphertext byte j (0..7) of block k (0..8) is encoded at hex pair
        p = 0x48*i + 0x12*m + 2*k   where i,m = divmod(j, 4)
  Payload plaintext: 9 slots x 8 bytes (see make_payload for known fields).
  CRC: nibble-table CRC32 (poly 0xEDB88320 reflected) over the 144 ASCII hex
        chars, seed 0x14 (Code) / 0x13 (Code2).

Cipher: 8-round Feistel-ish DES variant. IP/FP are SWAPMOVE permutation nets;
round r uses key dwords KS[31-4r : 28-4r] (k1..k4 = KS[e+3],KS[e+2],KS[e+1],
KS[e] with e = 28-4r); F(x; kA,kB) = SP-lookup of (kB^x) OR SP-lookup of
rol(kA^x, 28); rounds: ebx ^= F(eax), then eax ^= F(ebx).
Key: 07 1E C6 54 B7 01 7E 53 (schedule is constant, lifted below).

See RESEARCH.md in the repository for the full reverse-engineering story,
including the engine-side validation path (ClaimLicense, expiry check, the
second, engine-side Abil checker) and the E2E verification record.
"""

from .core import (decrypt_code, encrypt_code, gp6, interleave,  # noqa: F401
                  make_abil, make_name_field, make_payload, pad_name)
from .cli import build_reg, format_expiry  # noqa: F401

__all__ = [
    "decrypt_code", "encrypt_code", "gp6", "interleave",
    "make_abil", "make_name_field", "make_payload", "pad_name",
    "build_reg", "format_expiry",
]
__version__ = "1.0.0"
