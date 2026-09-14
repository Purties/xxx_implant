# cmp_nomatch.py - examine bytes of nomatch cases: old bytes at hook RVA
import struct
from capstone import Cs, CS_ARCH_X86, CS_MODE_64

OLD = r"d:\9-4#2\tools\GameAssembly_old_0902.dll"
old = open(OLD, "rb").read()
md = Cs(CS_ARCH_X86, CS_MODE_64)
md.skipdata = True

secs = [(0x1000, 0x400, 0x485400), (0x487000, 0x485800, 0x4e3c600)]
def va2raw(va):
    for v, r, s in secs:
        if v <= va < v + s:
            return r + (va - v)
    return None

def show(rva, n=48):
    raw = va2raw(rva)
    b = old[raw:raw+n]
    print(f"\n=== old GA {rva:#x} (raw {raw:#x}) ===")
    print("hex:", b.hex(" "))
    for ins in md.disasm(b, rva):
        print(f"  {ins.address:#x}: {ins.mnemonic} {ins.op_str}")
        if ins.address - rva > 40:
            break

# representative nomatch cases
for rva in (0x11be640, 0x11bef10, 0xf66e20, 0x1660650, 0xc0d8c0):
    show(rva)
