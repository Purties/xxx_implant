# docombatstep_hunt2.py - examine the 7 callers of new big-I (0x1214940); find DoCombatStep by structure
import struct
from capstone import Cs, CS_ARCH_X86, CS_MODE_64

NEW = r"C:\冒险岛online\mxdclassic\GameAssembly.dll"
data = open(NEW, "rb").read()
RAW0, VA0 = 0x488400, 0x489000
md = Cs(CS_ARCH_X86, CS_MODE_64)

CALLERS = [0x1033a1f, 0x10aa852, 0x10ddc53, 0x11078a9, 0x11459a8, 0x1161ec0, 0x12152da]

def raw(va):
    return RAW0 + (va - VA0)

for site in CALLERS:
    sfx = data[raw(site) + 5: raw(site) + 11]
    print(f"=== caller {site:#x}, suffix: {sfx.hex(' ')}")
    # try to find tiny-function start: sub rsp,imm8 at 0x10-aligned within [site-0x140, site-0x10]
    for back in range(0x10, 0x150, 0x10):
        cand = site - back
        if data[raw(cand):raw(cand)+3] == bytes.fromhex("48 83 ec"):
            # verify forward disasm reaches site
            ok = False
            for ins in md.disasm(data[raw(cand):raw(cand)+back+8], cand):
                if ins.address == site:
                    ok = True
                    break
                if ins.address > site:
                    break
            if ok:
                print(f"    tiny-start {cand:#x} (len to call {back:#x})")
                n = 0
                for ins in md.disasm(data[raw(cand):raw(cand)+0x100], cand):
                    print(f"      +{ins.address-cand:#05x}: {ins.mnemonic:8s} {ins.op_str}")
                    n += 1
                    if n >= 14:
                        break
