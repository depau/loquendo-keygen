"""Emulate Loquendo TTS7's license Code decryption natively with Unicorn.

Research oracle: maps the original LoqTTS7.dll at its preferred base
0x10000000 and calls the real crypto functions, so algorithmic questions
about the clean-room port in keygen/loqkey.py can be settled against the
original binary:
  - 0x10001570  DES key schedule (edx=8-byte key ptr, ecx=schedule out ptr,
    32 dwords)
  - 0x100012b0  block decrypt (eax=src 8 ct bytes, esi=out 8 bytes, stack
    arg = context: 0x70-byte header followed by the key schedule)

Usage (needs unicorn + pefile, and the original LoqTTS7.dll, which is NOT
distributed in this repository):
    LOQEMU_DLL=/path/to/LoqTTS7.dll python3 loqemu.py
Default DLL location is ./work/raffaele/pf/Loquendo/LTTS7/bin/LoqTTS7.dll.
"""
import os
import pefile
import struct
from unicorn import *
from unicorn.x86_const import *

DLL = os.environ.get(
    "LOQEMU_DLL",
    os.path.join(os.path.dirname(__file__),
                 "../work/raffaele/pf/Loquendo/LTTS7/bin/LoqTTS7.dll"))
BASE = 0x10000000
STACK = 0x00200000
STACK_SZ = 0x20000
_scratch = 0x00400000

def load():
    data = open(DLL, "rb").read()
    pe = pefile.PE(DLL, fast_load=True)
    mu = Uc(UC_ARCH_X86, UC_MODE_32)
    # map whole image sections
    for s in pe.sections:
        va = BASE + s.VirtualAddress
        sz = max(s.Misc_VirtualSize, s.SizeOfRawData)
        sz = (sz + 0xFFF) & ~0xFFF
        try:
            mu.mem_map(va, sz)
        except UcError:
            pass
        if s.SizeOfRawData:
            mu.mem_write(va, data[s.PointerToRawData:s.PointerToRawData + s.SizeOfRawData])
    mu.mem_map(STACK, STACK_SZ)
    mu.mem_map(_scratch, 0x10000)
    return mu

def run(mu, start, args=(), stop=None):
    """Fastcall-ish call: ecx/edx set, then push args + fake ret; stop at RET to magic."""
    MAGIC_RET = 0x90900000
    mu.mem_map(MAGIC_RET, 0x1000) if not mu.mem_read else None
    esp = STACK + STACK_SZ - 0x1000
    if stop is None:
        stop = MAGIC_RET
    # push args in reverse
    for a in reversed(args):
        esp -= 4
        mu.mem_write(esp, struct.pack("<I", a))
    esp -= 4
    mu.mem_write(esp, struct.pack("<I", MAGIC_RET))
    mu.reg_write(UC_X86_REG_ESP, esp)
    mu.reg_write(UC_X86_REG_EBP, STACK + 0x100)  # dummy
    mu.emu_start(start, stop)
    return mu

if __name__ == "__main__":
    mu = load()
    # 1) key schedule: edx=key ptr, ecx=out
    key = bytes([0x07,0x1e,0xc6,0x54,0xb7,0x01,0x7e,0x53])
    kp = _scratch
    mu.mem_write(kp, key)
    sched = _scratch + 0x100
    mu.reg_write(UC_X86_REG_EDX, kp)
    mu.reg_write(UC_X86_REG_ECX, sched)
    run(mu, 0x10001570)
    ks = struct.unpack("<32I", mu.mem_read(sched, 0x80))
    print("schedule:", " ".join(f"{k:08x}" for k in ks[:8]), "...")
    # 2) block decrypt via 0x100012b0: eax=src(8 ct bytes), esi=out(8 bytes), [pushed arg]=ks buf with +0x70 layout
    # out struct: 0x70 bytes then key schedule? cipher reads edi=out+0x70 -> schedule at out+0x70
    outbuf = sched  # cipher does edi = out + 0x70, walking DOWN through the schedule
    assert sched + 0x80 <= _scratch + 0x10000
    ct = _scratch + 0x2000
    out = _scratch + 0x2100
    def block(ciphertext):
        mu.mem_write(ct, ciphertext)
        mu.mem_write(out, b"\x00"*8)
        mu.reg_write(UC_X86_REG_EAX, ct)
        mu.reg_write(UC_X86_REG_ESI, out)
        esp = STACK + STACK_SZ - 0x2000
        esp -= 4; mu.mem_write(esp, struct.pack("<I", outbuf)); # push out struct
        esp -= 4; mu.mem_write(esp, struct.pack("<I", 0x90900000))
        mu.reg_write(UC_X86_REG_ESP, esp)
        mu.emu_start(0x100012b0, 0x90900000)
        return bytes(mu.mem_read(out, 8))
    # known-good Code
    CODE = "D2FCEFB9875BAF17AF2242B47077E3191219A72AFDBC3CFF8CD68C8811FEEE0B6D489E482514244C13B4313D3148F1C355B63A52A652761292A3CDCED759D77AE77BBA3DECA1D9A100001556"
    assert len(CODE) == 152, len(CODE)
    payload = CODE[:144]
    crc_field = CODE[144:]
    print("CRC field:", crc_field)
    # scatter: block k in 0..8: iteration i in 0..1 reads pairs at 0x48*i + 0x12*m + 2k (m=0..3)?
    # From disasm: iteration i(0..7) base=ebx+0x48*i reads pairs at +0,+0x12,+0x24,+0x36 -> 4 bytes.
    # With 9 blocks the ebx base advances 2 chars per block. positions = 0x48*i + 0x12*m + 2*k.
    def nib(c):
        o = ord(c)
        return o - 0x30 if 0x30 <= o <= 0x39 else o - 0x37
    plain = b""
    for k in range(9):
        ctbytes = bytearray(8)
        for i in range(2):
            for m in range(4):
                p = 0x48*i + 0x12*m + 2*k
                ctbytes[i*4 + m] = (nib(payload[p]) << 4) | nib(payload[p+1])
        pt = block(bytes(ctbytes))
        plain += pt
        print(f"block {k}: ct={bytes(ctbytes).hex()} -> pt={pt.hex()} | {pt!r}")
    print("PLAINTEXT 72 bytes:", plain.hex())
    print(repr(plain))
