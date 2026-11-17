"""Loquendo TTS 7 'UNIFIED Licensing SW' — license Code crypto, pure Python.

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
"""
import struct

_M32 = 0xFFFFFFFF


def _rol(x, n):
    return ((x << n) | (x >> (32 - n))) & _M32


def _ror(x, n):
    return ((x >> n) | (x << (32 - n))) & _M32


# 8 x 64 dwords at 0x10095708..0x10095e08 in LoqTTS7.dll
_SP = [
    [0x00820200, 0x00020000, 0x80800000, 0x80820200, 0x00800000, 0x80020200,
     0x80020000, 0x80800000, 0x80020200, 0x00820200, 0x00820000, 0x80000200,
     0x80800200, 0x00800000, 0x00000000, 0x80020000, 0x00020000, 0x80000000,
     0x00800200, 0x00020200, 0x80820200, 0x00820000, 0x80000200, 0x00800200,
     0x80000000, 0x00000200, 0x00020200, 0x80820000, 0x00000200, 0x80800200,
     0x80820000, 0x00000000, 0x00000000, 0x80820200, 0x00800200, 0x80020000,
     0x00820200, 0x00020000, 0x80000200, 0x00800200, 0x80820000, 0x00000200,
     0x00020200, 0x80800000, 0x80020200, 0x80000000, 0x80800000, 0x00820000,
     0x80820200, 0x00020200, 0x00820000, 0x80800200, 0x00800000, 0x80000200,
     0x80020000, 0x00000000, 0x00020000, 0x00800000, 0x80800200, 0x00820200,
     0x80000000, 0x80820000, 0x00000200, 0x80020200],
    [0x10042004, 0x00000000, 0x00042000, 0x10040000, 0x10000004, 0x00002004,
     0x10002000, 0x00042000, 0x00002000, 0x10040004, 0x00000004, 0x10002000,
     0x00040004, 0x10042000, 0x10040000, 0x00000004, 0x00040000, 0x10002004,
     0x10040004, 0x00002000, 0x00042004, 0x10000000, 0x00000000, 0x00040004,
     0x10002004, 0x00042004, 0x10042000, 0x10000004, 0x10000000, 0x00040000,
     0x00002004, 0x10042004, 0x00040004, 0x10042000, 0x10002000, 0x00042004,
     0x10042004, 0x00040004, 0x10000004, 0x00000000, 0x10000000, 0x00002004,
     0x00040000, 0x10040004, 0x00002000, 0x10000000, 0x00042004, 0x10002004,
     0x10042000, 0x00002000, 0x00000000, 0x10000004, 0x00000004, 0x10042004,
     0x00042000, 0x10040000, 0x10040004, 0x00040000, 0x00002004, 0x10002000,
     0x10002004, 0x00000004, 0x10040000, 0x00042000],
    [0x41000000, 0x01010040, 0x00000040, 0x41000040, 0x40010000, 0x01000000,
     0x41000040, 0x00010040, 0x01000040, 0x00010000, 0x01010000, 0x40000000,
     0x41010040, 0x40000040, 0x40000000, 0x41010000, 0x00000000, 0x40010000,
     0x01010040, 0x00000040, 0x40000040, 0x41010040, 0x00010000, 0x41000000,
     0x41010000, 0x01000040, 0x40010040, 0x01010000, 0x00010040, 0x00000000,
     0x01000000, 0x40010040, 0x01010040, 0x00000040, 0x40000000, 0x00010000,
     0x40000040, 0x40010000, 0x01010000, 0x41000040, 0x00000000, 0x01010040,
     0x00010040, 0x41010000, 0x40010000, 0x01000000, 0x41010040, 0x40000000,
     0x40010040, 0x41000000, 0x01000000, 0x41010040, 0x00010000, 0x01000040,
     0x41000040, 0x00010040, 0x01000040, 0x00000000, 0x41010000, 0x40000040,
     0x41000000, 0x40010040, 0x00000040, 0x01010000],
    [0x00100402, 0x04000400, 0x00000002, 0x04100402, 0x00000000, 0x04100000,
     0x04000402, 0x00100002, 0x04100400, 0x04000002, 0x04000000, 0x00000402,
     0x04000002, 0x00100402, 0x00100000, 0x04000000, 0x04100002, 0x00100400,
     0x00000400, 0x00000002, 0x00100400, 0x04000402, 0x04100000, 0x00000400,
     0x00000402, 0x00000000, 0x00100002, 0x04100400, 0x04000400, 0x04100002,
     0x04100402, 0x00100000, 0x04100002, 0x00000402, 0x00100000, 0x04000002,
     0x00100400, 0x04000400, 0x00000002, 0x04100000, 0x04000402, 0x00000000,
     0x00000400, 0x00100002, 0x00000000, 0x04100002, 0x04100400, 0x00000400,
     0x04000000, 0x04100402, 0x00100402, 0x00100000, 0x04100402, 0x00000002,
     0x04000400, 0x00100402, 0x00100002, 0x00100400, 0x04100000, 0x04000402,
     0x00000402, 0x04000000, 0x04000002, 0x04100400],
    [0x02000000, 0x00004000, 0x00000100, 0x02004108, 0x02004008, 0x02000100,
     0x00004108, 0x02004000, 0x00004000, 0x00000008, 0x02000008, 0x00004100,
     0x02000108, 0x02004008, 0x02004100, 0x00000000, 0x00004100, 0x02000000,
     0x00004008, 0x00000108, 0x02000100, 0x00004108, 0x00000000, 0x02000008,
     0x00000008, 0x02000108, 0x02004108, 0x00004008, 0x02004000, 0x00000100,
     0x00000108, 0x02004100, 0x02004100, 0x02000108, 0x00004008, 0x02004000,
     0x00004000, 0x00000008, 0x02000008, 0x02000100, 0x02000000, 0x00004100,
     0x02004108, 0x00000000, 0x00004108, 0x02000000, 0x00000100, 0x00004008,
     0x02000108, 0x00000100, 0x00000000, 0x02004108, 0x02004008, 0x02004100,
     0x00000108, 0x00004000, 0x00004100, 0x02004008, 0x02000100, 0x00000108,
     0x00000008, 0x00004108, 0x02004000, 0x02000008],
    [0x20000010, 0x00080010, 0x00000000, 0x20080800, 0x00080010, 0x00000800,
     0x20000810, 0x00080000, 0x00000810, 0x20080810, 0x00080800, 0x20000000,
     0x20000800, 0x20000010, 0x20080000, 0x00080810, 0x00080000, 0x20000810,
     0x20080010, 0x00000000, 0x00000800, 0x00000010, 0x20080800, 0x20080010,
     0x20080810, 0x20080000, 0x20000000, 0x00000810, 0x00000010, 0x00080800,
     0x00080810, 0x20000800, 0x00000810, 0x20000000, 0x20000800, 0x00080810,
     0x20080800, 0x00080010, 0x00000000, 0x20000800, 0x20000000, 0x00000800,
     0x20080010, 0x00080000, 0x00080010, 0x20080810, 0x00080800, 0x00000010,
     0x20080810, 0x00080800, 0x00080000, 0x20000810, 0x20000010, 0x20080000,
     0x00080810, 0x00000000, 0x00000800, 0x20000010, 0x20000810, 0x20080800,
     0x20080000, 0x00000810, 0x00000010, 0x20080010],
    [0x00001000, 0x00000080, 0x00400080, 0x00400001, 0x00401081, 0x00001001,
     0x00001080, 0x00000000, 0x00400000, 0x00400081, 0x00000081, 0x00401000,
     0x00000001, 0x00401080, 0x00401000, 0x00000081, 0x00400081, 0x00001000,
     0x00001001, 0x00401081, 0x00000000, 0x00400080, 0x00400001, 0x00001080,
     0x00401001, 0x00001081, 0x00401080, 0x00000001, 0x00001081, 0x00401001,
     0x00000080, 0x00400000, 0x00001081, 0x00401000, 0x00401001, 0x00000081,
     0x00001000, 0x00000080, 0x00400000, 0x00401001, 0x00400081, 0x00001081,
     0x00001080, 0x00000000, 0x00000080, 0x00400001, 0x00000001, 0x00400080,
     0x00000000, 0x00400081, 0x00400080, 0x00001080, 0x00000081, 0x00001000,
     0x00401081, 0x00400000, 0x00401080, 0x00000001, 0x00001001, 0x00401081,
     0x00400001, 0x00401080, 0x00401000, 0x00001001],
    [0x08200020, 0x08208000, 0x00008020, 0x00000000, 0x08008000, 0x00200020,
     0x08200000, 0x08208020, 0x00000020, 0x08000000, 0x00208000, 0x00008020,
     0x00208020, 0x08008020, 0x08000020, 0x08200000, 0x00008000, 0x00208020,
     0x00200020, 0x08008000, 0x08208020, 0x08000020, 0x00000000, 0x00208000,
     0x08000000, 0x00200000, 0x08008020, 0x08200020, 0x00200000, 0x00008000,
     0x08208000, 0x00000020, 0x00200000, 0x00008000, 0x08000020, 0x08208020,
     0x00008020, 0x08000000, 0x00000000, 0x00208000, 0x08200020, 0x08008020,
     0x08008000, 0x00200020, 0x08208000, 0x00000020, 0x00200020, 0x08008000,
     0x08208020, 0x00200000, 0x08200000, 0x08000020, 0x00208000, 0x00008020,
     0x08008020, 0x08200000, 0x00000020, 0x08208000, 0x00208020, 0x00000000,
     0x08000000, 0x08200020, 0x00008000, 0x00208020],
]
# SP-table VA -> index (which table the F function reads for which byte lane):
# edx lanes: byte3->0x10095d08=SP[6], byte2->0x10095b08=SP[4], byte1->0x10095908=SP[2], byte0->0x10095708=SP[0]
# ecx lanes: byte3->0x10095e08=SP[7], byte2->0x10095c08=SP[5], byte1->0x10095a08=SP[3], byte0->0x10095808=SP[1]
_EDX_LANES = (_SP[6], _SP[4], _SP[2], _SP[0])
_ECX_LANES = (_SP[7], _SP[5], _SP[3], _SP[1])

# Key schedule for hardcoded key 07 1E C6 54 B7 01 7E 53 (0x10001570), 32 dwords
_KS = [
    0x1c0f262a, 0x61a14011, 0x3f213d0c, 0xa1723002, 0x3e1c0029, 0xa07213a2,
    0x1a1a3e01, 0x80f0a033, 0x1a32143a, 0xc1928282, 0x38172808, 0xc3905272,
    0x1c073011, 0x52d39083, 0x0f2b0d0d, 0x5210c0a3, 0x2a341326, 0xa2e14211,
    0x3233201e, 0x90e08151, 0x37330310, 0xc0c160c2, 0x36190826, 0xe2d1f102,
    0x1e190325, 0x12f20052, 0x0f190512, 0x11913132, 0x0d1f1235, 0xa1906340,
    0x31211801, 0xb07182a3,
]

# CRC nibble tables from LTTS7Util.dll 0x1006daac / 0x1006dacc (word[16])
_CRC_TLO = [0x0000, 0xc0c1, 0xc181, 0x0140, 0xc301, 0x03c0, 0x0280, 0xc241,
            0xc601, 0x06c0, 0x0780, 0xc741, 0x0500, 0xc5c1, 0xc481, 0x0440]
_CRC_THI = [0x0000, 0xcc01, 0xd801, 0x1400, 0xf001, 0x3c00, 0x2800, 0xe401,
            0xa001, 0x6c00, 0x7800, 0xb401, 0x5000, 0x9c01, 0x8801, 0x4600]


def _s(edx, ecx):
    s = _EDX_LANES[0][(edx >> 24) & 0x3f] | _EDX_LANES[1][(edx >> 16) & 0x3f] \
      | _EDX_LANES[2][(edx >> 8) & 0x3f] | _EDX_LANES[3][edx & 0x3f]
    s |= _ECX_LANES[0][(ecx >> 24) & 0x3f] | _ECX_LANES[1][(ecx >> 16) & 0x3f] \
      | _ECX_LANES[2][(ecx >> 8) & 0x3f] | _ECX_LANES[3][ecx & 0x3f]
    return s


def _f(x, k_first, k_second):
    """F(x; k1, k2) = S(k2 ^ x, rol(k1 ^ x, 28)) — k1 from [edi+0xc] lane."""
    return _s(k_second ^ x, _rol(k_first ^ x, 28))


def decrypt_block(ct8):
    d0, d1 = struct.unpack("<II", ct8)
    eax, ecx = d0, d1
    edx = ((ecx >> 4) ^ eax) & 0x0F0F0F0F; eax ^= edx; ecx ^= (edx << 4) & _M32
    edx = ((eax >> 16) ^ ecx) & 0x0000FFFF; ecx ^= edx; eax ^= (edx << 16) & _M32
    edx = ((ecx >> 2) ^ eax) & 0x33333333; eax ^= edx; ecx ^= (edx * 4) & _M32
    edx = ((eax >> 8) ^ ecx) & 0x00FF00FF; ecx ^= edx; eax ^= (edx << 8) & _M32
    edx = ((ecx >> 1) ^ eax) & 0x55555555
    ebx = ((edx * 2) & _M32) ^ ecx
    eax ^= edx
    eax = _rol(eax, 1); ebx = _rol(ebx, 1)
    for r in range(8):
        e = 28 - 4 * r
        ebx ^= _f(eax, _KS[e + 3], _KS[e + 2])
        eax ^= _f(ebx, _KS[e + 1], _KS[e])
    eax = _ror(eax, 1); ebx = _ror(ebx, 1)
    a, c = eax, ebx
    edx = ((a >> 1) ^ c) & 0x55555555; c ^= edx; a ^= (edx * 2) & _M32
    edx = ((c >> 8) ^ a) & 0x00FF00FF; a ^= edx; c ^= (edx << 8) & _M32
    edx = ((a >> 2) ^ c) & 0x33333333; c ^= edx; a ^= (edx * 4) & _M32
    edx = ((c >> 16) ^ a) & 0x0000FFFF; a ^= edx; c ^= (edx << 16) & _M32
    edx = ((a >> 4) ^ c) & 0x0F0F0F0F
    return struct.pack("<II", edx ^ c, ((edx << 4) & _M32) ^ a)


def encrypt_block(pt8):
    p0, p1 = struct.unpack("<II", pt8)
    edx = ((p1 >> 4) ^ p0) & 0x0F0F0F0F
    c = p0 ^ edx
    a = p1 ^ ((edx << 4) & _M32)
    t = ((c >> 16) ^ a) & 0x0000FFFF; a ^= t; c ^= (t << 16) & _M32
    t = ((a >> 2) ^ c) & 0x33333333; c ^= t; a ^= (t * 4) & _M32
    t = ((c >> 8) ^ a) & 0x00FF00FF; a ^= t; c ^= (t << 8) & _M32
    t = ((a >> 1) ^ c) & 0x55555555; c ^= t; a ^= (t * 2) & _M32
    eax, ebx = _rol(a, 1), _rol(c, 1)
    for r in reversed(range(8)):
        e = 28 - 4 * r
        eax ^= _f(ebx, _KS[e + 1], _KS[e])
        ebx ^= _f(eax, _KS[e + 3], _KS[e + 2])
    a, c = _ror(eax, 1), _ror(ebx, 1)
    t = ((c >> 1) ^ a) & 0x55555555
    ecx = c ^ ((t * 2) & _M32)
    eax = a ^ t
    a, c = eax, ecx
    t = ((a >> 8) ^ c) & 0x00FF00FF; c ^= t; a ^= (t << 8) & _M32
    t = ((c >> 2) ^ a) & 0x33333333; a ^= t; c ^= (t * 4) & _M32
    t = ((a >> 16) ^ c) & 0x0000FFFF; c ^= t; a ^= (t << 16) & _M32
    t = ((c >> 4) ^ a) & 0x0F0F0F0F; a ^= t; c ^= (t << 4) & _M32
    return struct.pack("<II", a, c)


def crc_update(data, crc):
    """ELQCrcGetChecksum (LTTS7Util.dll 0x4640): in-place nibble-table CRC32 update."""
    for byte in data:
        al = (byte ^ (crc & 0xFF)) & 0xFF
        crc = (crc >> 8) ^ _CRC_TLO[al & 0xF] ^ _CRC_THI[al >> 4]
    return crc & _M32


def _nib(c):
    o = ord(c)
    return o - 0x30 if 0x30 <= o <= 0x39 else o - 0x37


def scatter(ct72):
    """72 ciphertext bytes -> 144 hex chars using the Loquendo scatter."""
    out = ["\x00", "\x00"] * 72
    for k in range(9):
        for j in range(8):
            i, m = divmod(j, 4)
            p = 0x48 * i + 0x12 * m + 2 * k
            h = "%02X" % ct72[8 * k + j]
            out[p], out[p + 1] = h[0], h[1]
    return "".join(out)


def gather(hex144):
    """144 hex chars -> 72 ciphertext bytes (inverse of scatter)."""
    ct = bytearray(72)
    for k in range(9):
        for j in range(8):
            i, m = divmod(j, 4)
            p = 0x48 * i + 0x12 * m + 2 * k
            ct[8 * k + j] = (_nib(hex144[p]) << 4) | _nib(hex144[p + 1])
    return bytes(ct)


def make_payload(name, abil, expiry="99999999"):
    """Build the 72-byte plaintext payload.

    Layout (verified against the shipped known-good Code):
      a 32-byte name buffer holds copies of name+"\\0" written at stride
      len(name)+1 (offsets 0, L+1, 2(L+1), ...), each truncated + NUL-
      terminated at the 32-byte boundary (Delphi StrLCopy semantics);
      slot0=[0:8], slot1=[8:16], slot3=[16:24], slot4=[24:32] of that buffer,
      with the expiry string spliced in as slot 2 between slot1 and slot3;
      slot 2 = expiry, "99999999" = permanent, else YYYYMMDD text;
      slots 5,8 = the 16-char Abil string (voice abilities) split in half;
      slot 7 = 0xFF (unused).
    """
    nb = name.encode()
    unit = nb + b"\x00"
    field = bytearray(32)
    off = 0
    while off < 32:
        n = min(len(unit), 32 - off)
        # StrLCopy: copy at most n-1 chars, then NUL-terminate (if n > 0)
        field[off:off + n] = unit[:n - 1].ljust(n, b"\x00") if n else b""
        off += len(unit)
    slot2 = expiry.encode().ljust(8, b"\x00")[:8]
    return (bytes(field[0:8]) + bytes(field[8:16]) + slot2
            + bytes(field[16:24]) + bytes(field[24:32])
            + abil.encode()[:8] + b"\xff" * 8
            + abil.encode()[8:16] + b"\xff" * 8)
def decrypt_code(code):
    """Full Code string (152 chars) -> 72-byte plaintext payload."""
    hex144 = code[:144]
    assert len(hex144) == 144
    expected = int(code[144:], 16)
    if crc_update(hex144.encode(), 0x14) != expected:
        raise ValueError("CRC mismatch")
    return b"".join(decrypt_block(gather(hex144)[8 * k:8 * k + 8]) for k in range(9))


def encrypt_code(payload72, crc_seed=0x14):
    """72-byte plaintext payload -> full 152-char Code string."""
    assert len(payload72) == 72
    hex144 = scatter(b"".join(encrypt_block(payload72[8 * k:8 * k + 8]) for k in range(9)))
    return hex144 + "%08X" % crc_update(hex144.encode(), crc_seed)


_B62 = b"0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"


def _srem(a, b):
    """C signed % (truncation toward zero)."""
    q = abs(a) // abs(b)
    if (a < 0) != (b < 0):
        q = -q
    return a - q * b


def interleave(mac, user):
    """44-char MachineID seed: MAC/user interleave (Patch.exe FUN_00452a38).

    MAC is the 17-char "XX:XX:..." string. Per group EBP in (1,4,7,10,13,16):
    dest[EBP-1],dest[EBP] = MAC[EBP-1],MAC[EBP]; dest[EBP+1] = user[k].
    Tail: user[6:] fills dest[18..43] until its NUL (which terminates the string;
    unfilled dest tail stays '_' but is never reached). Returns the NUL-terminated
    length, i.e. min(18 + len(user) - 6, 44) chars.
    """
    assert len(mac) == 17
    d = ["_"] * 44
    k = 0
    for ebp in (1, 4, 7, 10, 13, 16):
        d[ebp - 1] = mac[ebp - 1]
        d[ebp] = mac[ebp]
        d[ebp + 1] = user[k] if k < len(user) else "\0"
        k += 1
    i = 18
    while k < len(user) and i < 44:
        d[i] = user[k]
        k += 1
        i += 1
    return "".join(d[:i])


def gp6(s):
    """16-char Abil from the interleave (Patch.exe FUN_004528c0).

    seed = 0x36; over i = 0..len-1 (s[len] = NUL = 0 participates):
      seed *= s[i] + s[i+1] - 1   (signed 32-bit wrap)
    idx0 = |seed % len| (signed %); B[0] = T[(s[idx0]*0x13) % 62];
    B[j] = T[(B[j-1]*0x77 + s[(idx0 + j - 1) % len]) % 62]   (raw ASCII values)
    """
    n = len(s)
    seed = 0x36
    for i in range(n):
        nxt = ord(s[i + 1]) if i + 1 < n else 0
        seed = (seed * (ord(s[i]) + nxt - 1)) & 0xFFFFFFFF
        if seed >= 1 << 31:
            seed -= 1 << 32
    idx0 = abs(_srem(seed, n))
    out = [_B62[(ord(s[idx0]) * 0x13) % 62]]
    for j in range(1, 16):
        idx = (idx0 + j - 1) % n
        out.append(_B62[(out[j - 1] * 0x77 + ord(s[idx])) % 62])
    return bytes(out).decode()


def make_abil(mac, user):
    """Full Abil derivation: interleave(MAC, user) -> gp6."""
    return gp6(interleave(mac, user))


def make_name_field(name):
    """32-char cyclic name field with '+'-padding (Patch.exe 0x453703).

    Usernames shorter than 7 chars are padded with '+' to exactly 7 (both the
    registry Name and the cyclic field carry the padding); then name+"\\0"
    repeats at stride len+1, byte 31 NUL.
    """
    if len(name) < 7:
        name = name + "+" * (7 - len(name))
    field = bytearray(32)
    unit = name.encode() + b"\x00"
    off = 0
    while off < 32:
        n = min(len(unit), 32 - off)
        field[off:off + n] = unit[:n - 1].ljust(n, b"\x00")
        off += len(unit)
    field[31] = 0
    return bytes(field)




_KNOWN_GOOD = ("D2FCEFB9875BAF17AF2242B47077E3191219A72AFDBC3CFF8CD68C8811FEEE0B"
               "6D489E482514244C13B4313D3148F1C355B63A52A652761292A3CDCED759D77A"
               "E77BBA3DECA1D9A100001556")

if __name__ == "__main__":
    pt = decrypt_code(_KNOWN_GOOD)
    print("known-good payload:", pt.hex())
    print(repr(pt))
    # Full generative path: (MAC, username) -> Abil -> payload -> Code
    abil = make_abil("7A:8B:9C:1D:2E:3F", "wineuser")
    print("derived Abil      :", abil)
    assert abil == "IT192MU2NQk0YIa6", abil
    regen = encrypt_code(make_payload("wineuser", abil))
    print("regenerated Code  :", regen)
    print("MATCH             :", regen == _KNOWN_GOOD)
    assert regen == _KNOWN_GOOD
