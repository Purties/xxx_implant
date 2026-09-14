# func_boundaries.py - from a start RVA, linearly scan new GA il2cpp for function boundaries
# (ret/int3 followed by nop padding -> next aligned function start). Report first N boundaries.
import sys
from capstone import Cs, CS_ARCH_X86, CS_MODE_64

NEW = r"C:\冒险岛online\mxdclassic\GameAssembly.dll"
data = open(NEW, "rb").read()
RAW0, VA0 = 0x488400, 0x489000

start = int(sys.argv[1], 16)
maxb = int(sys.argv[2]) if len(sys.argv) > 2 else 8

md = Cs(CS_ARCH_X86, CS_MODE_64)

NOP_PREFIXES = (0x66,)  # multi-byte nop family: 66 0f 1f ... / 0f 1f ...

def is_nop_run(raw, end):
    """from raw, consume nop-like bytes until next 0x10 boundary; return next func raw or None"""
    i = raw
    while i < len(data):
        b = data[i]
        if b == 0x90:
            i += 1
            continue
        if b == 0x66 or b == 0x2e:
            i += 1
            continue
        if b == 0x0f and data[i+1] in (0x1f,):
            # 0f 1f xx ... length from modrm; approximate: skip known nop lengths by disasm
            for ins in md.disasm(data[i:i+16], 0):
                if ins.mnemonic == "nop":
                    i += ins.size
                    break
            else:
                return None
            continue
        if b == 0x00:  # padding zeros between functions
            i += 1
            continue
        if b == 0xcc:
            i += 1
            continue
        break
    # align up to 0x10
    va = VA0 + (i - RAW0)
    return va & ~0xF if va % 0x10 == 0 else (va + (0x10 - va % 0x10))

rva = start
for _ in range(maxb):
    raw = RAW0 + (rva - VA0)
    # linear disasm until ret
    end_va = None
    for ins in md.disasm(data[raw:raw+0x4000], rva):
        if ins.mnemonic in ("ret",):
            end_va = ins.address + ins.size
            break
    if end_va is None:
        print(f"{rva:#x}: no ret within 0x4000")
        break
    nxt = is_nop_run(RAW0 + (end_va - VA0), end_va)
    print(f"func {rva:#x} .. {end_va:#x} (len {end_va-rva:#x}) -> next {nxt:#x}")
    rva = nxt
