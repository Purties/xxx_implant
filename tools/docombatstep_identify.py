# docombatstep_identify.py - among tail-pattern hits, find the one whose jump-table stub calls new SetImpactNext (0x1214510)
import struct
from capstone import Cs, CS_ARCH_X86, CS_MODE_64

NEW = r"C:\冒险岛online\mxdclassic\GameAssembly.dll"
data = open(NEW, "rb").read()
RAW0, RAW1, VA0 = 0x488400, 0x488400 + 0x4efb600, 0x489000

def rva2raw(rva):
    return RAW0 + (rva - VA0)

tails = [0x4d9d60, 0x4d9dd2, 0x563396, 0x5b7954, 0xa076bc, 0xa54fdc,
         0xd3117c, 0xd71abd, 0x11afd04, 0x16395ce, 0x1c1c1ed, 0x1c596f4, 0x1d1f134]

TARGETS = {0x1214520: "SetImpactNext(big)", 0x1214510: "tiny-flag", 0x12144f0: "SetVelocity"}

md = Cs(CS_ARCH_X86, CS_MODE_64)

for t in tails:
    raw = rva2raw(t)
    w0, w1 = max(RAW0, raw - 0x200), min(RAW1, raw + 0x200)
    code = data[w0:w1]
    found = []
    for ins in md.disasm(code, VA0 + (w0 - RAW0)):
        if ins.mnemonic == "call" and ins.op_str.startswith("0x"):
            tgt = int(ins.op_str, 16)
            if tgt in TARGETS:
                found.append((hex(ins.address), TARGETS[tgt]))
    print(f"tail {t:#x}: calls to known hooks -> {found if found else '-'}")
