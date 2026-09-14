# rva_migrate.py - Phase1: parse dispatch code -> (label, old_rva) pairs
#                  Phase2: masked byte-pattern match old GA -> new GA -> new_rva
import struct
from capstone import Cs, CS_ARCH_X86, CS_MODE_64
from capstone.x86 import X86_OP_MEM, X86_REG_RIP

DUMP = r"d:\9-4#2\xxx\analysis\memscan\region_0_0x269C000.bin"
OLD  = r"d:\9-4#2\tools\GameAssembly_old_0902.dll"
NEW  = r"C:\冒险岛online\mxdclassic\GameAssembly.dll"

dump = open(DUMP, "rb").read()
old  = open(OLD, "rb").read()
new  = open(NEW, "rb").read()
print(f"dump {len(dump):#x}  old {len(old):#x}  new {len(new):#x}")

md = Cs(CS_ARCH_X86, CS_MODE_64)
md.detail = True

# ---------- Phase 1: dispatch parse ----------
# dump file offset == address - 0x180000000 (assumed); dispatch code ~0x126000..0x129000
CODE_LO, CODE_HI = 0x126000, 0x129000
STR_LO, STR_HI = 0x180000, 0x1A0000   # label string area (dump offsets)

def read_cstr(off):
    end = dump.find(b"\x00", off)
    if end < 0 or end - off > 120:
        return None
    s = dump[off:end]
    if s and all(32 <= b < 127 for b in s):
        return s.decode()
    return None

hook_leas = []   # (insn_off, rva)
label_leas = []  # (insn_off, str_off)
code = dump[CODE_LO:CODE_HI]
for ins in md.disasm(code, CODE_LO):
    if ins.mnemonic != "lea":
        continue
    # operands via detail
    ops = ins.operands
    if len(ops) != 2 or ops[1].type != X86_OP_MEM:
        continue
    mem = ops[1].mem
    # rip-relative: base == RIP
    if mem.base == X86_REG_RIP:
        tgt = ins.address + ins.size + mem.disp
        if STR_LO <= tgt < STR_HI:
            s = read_cstr(tgt)
            if s:
                label_leas.append((ins.address, tgt, s))
    else:
        # base reg + disp32, large imm -> GameAssembly rva
        if 0x10000 <= mem.disp < 0x4000000:
            hook_leas.append((ins.address, mem.disp))

print(f"\nhook leas: {len(hook_leas)}   label leas: {len(label_leas)}")

# pair: for each hook lea, nearest label lea within +0x80/-0x20
pairs = []
used = set()
for ha, rva in hook_leas:
    best = None
    for la, tgt, s in label_leas:
        d = la - ha
        if -0x20 <= d <= 0x80 and la not in used:
            if best is None or abs(d) < abs(best[0] - ha):
                best = (la, tgt, s)
    if best:
        used.add(best[0])
        pairs.append((best[2], rva, ha))

print(f"\n=== pairs (label <- old_rva) ===")
seen = {}
for s, rva, ha in pairs:
    seen.setdefault(s, rva)
    print(f"  {rva:#010x}  {s}")
print(f"unique labels: {len(seen)}")

import json
with open(r"d:\9-4#2\xxx\analysis\rva_labels.json", "w") as f:
    json.dump({"pairs": [(s, rva) for s, rva, _ in pairs]}, f, indent=1)
print("saved rva_labels.json")
