# func_of_callsite.py - find containing function start of a call site (heuristic: aligned, padding-preceded) and disasm head
import sys
from capstone import Cs, CS_ARCH_X86, CS_MODE_64

NEW = r"C:\冒险岛online\mxdclassic\GameAssembly.dll"
data = open(NEW, "rb").read()
RAW0, VA0 = 0x488400, 0x489000

def preceded_by_padding(raw):
    """check bytes before raw are nop/int3/zero padding (at least 2 bytes)"""
    pad = 0
    i = raw - 1
    while i >= 0 and data[i] in (0x90, 0xcc, 0x00):
        pad += 1
        i -= 1
    if pad >= 2:
        return True
    # multi-byte nop: ... 66 0f 1f 84 00 00 00 00 00  or 66 66 ...
    j = raw - 1
    seen = 0
    while j >= 0 and data[j] in (0x66, 0x2e, 0x84, 0x00, 0x1f, 0x0f) and seen < 12:
        if data[j] == 0x1f:
            return True
        j -= 1
        seen += 1
    return False

PROLOGUES = [
    bytes.fromhex("48 83 ec"),           # sub rsp, imm8
    bytes.fromhex("48 81 ec"),           # sub rsp, imm32
    bytes.fromhex("40 53"),              # push rbx (etc.)
    bytes.fromhex("40 55"),
    bytes.fromhex("40 56"),
    bytes.fromhex("40 57"),
    bytes.fromhex("41 54"),
    bytes.fromhex("41 55"),
    bytes.fromhex("41 56"),
    bytes.fromhex("41 57"),
    bytes.fromhex("53"), bytes.fromhex("55"), bytes.fromhex("56"), bytes.fromhex("57"),
]

def find_start(site_rva, maxback=0x600):
    site_raw = RAW0 + (site_rva - VA0)
    best = None
    lo = max(RAW0, site_raw - maxback)
    # candidate starts: 0x10-aligned addresses with prologue bytes, preceded by padding
    for a in range(site_raw - (site_raw % 0x10), lo, -0x10):
        if any(data[a:a+len(p)] == p for p in PROLOGUES) and preceded_by_padding(a):
            best = a
            break
    return VA0 + (best - RAW0) if best else None

md = Cs(CS_ARCH_X86, CS_MODE_64)
for arg in sys.argv[1:]:
    site = int(arg, 16)
    st = find_start(site)
    print(f"=== callsite {site:#x} -> func start {st and hex(st)} (dist {site - st if st else -1:#x}) ===")
    if st:
        raw = RAW0 + (st - VA0)
        n = 0
        for ins in md.disasm(data[raw:raw+0x100], st):
            print(f"  +{ins.address - st:#05x}: {ins.mnemonic:8s} {ins.op_str}")
            n += 1
            if n >= 18:
                break
