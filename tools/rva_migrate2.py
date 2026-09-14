# rva_migrate2.py - precise dispatch parse: pair via adjacent global descriptor slots
import struct
from capstone import Cs, CS_ARCH_X86, CS_MODE_64
from capstone.x86 import X86_OP_MEM, X86_REG_RIP, X86_REG_RAX

DUMP = r"d:\9-4#2\xxx\analysis\memscan\region_0_0x269C000.bin"
dump = open(DUMP, "rb").read()

md = Cs(CS_ARCH_X86, CS_MODE_64)
md.detail = True
md.skipdata = True

CODE_LO, CODE_HI = 0x100000, 0x140000
STR_LO, STR_HI = 0x100000, 0x200000

def read_cstr(off):
    end = dump.find(b"\x00", off)
    if end < 0 or end - off > 120 or end == off:
        return None
    s = dump[off:end]
    if all(32 <= b < 127 for b in s):
        return s.decode()
    return None

insns = []
code = dump[CODE_LO:CODE_HI]
for ins in md.disasm(code, CODE_LO):
    insns.append(ins)

# walk: detect
#  A) hook: lea rX, [rBase + bigimm] ; ... ; mov [rip+G], rX     -> (G, rva)
#  B) label: lea rX, [rip+tgt(str)] ; ... ; mov [rip+G], rX      -> (G, string)
hooks = {}   # G -> (rva, addr)
labels = {}  # G -> (string, addr)

N = len(insns)
for i, ins in enumerate(insns):
    if ins.mnemonic == "lea" and len(ins.operands) == 2 and ins.operands[1].type == X86_OP_MEM:
        mem = ins.operands[1].mem
        dstreg = ins.operands[0].reg
        if mem.base == X86_REG_RIP:
            tgt = ins.address + ins.size + mem.disp
            if STR_LO <= tgt < STR_HI:
                s = read_cstr(tgt)
                if s is None:
                    continue
                # find following mov [rip+G], dstreg within 6 insns
                for j in range(i+1, min(i+7, N)):
                    ni = insns[j]
                    if ni.mnemonic == "mov" and len(ni.operands) == 2:
                        o0, o1 = ni.operands
                        if o0.type == X86_OP_MEM and o0.mem.base == X86_REG_RIP and o1.reg == dstreg:
                            G = ni.address + ni.size + o0.mem.disp
                            labels[G] = (s, ins.address)
                            break
        else:
            if 0x10000 <= mem.disp < 0x4000000:
                for j in range(i+1, min(i+7, N)):
                    ni = insns[j]
                    if ni.mnemonic == "mov" and len(ni.operands) == 2:
                        o0, o1 = ni.operands
                        if o0.type == X86_OP_MEM and o0.mem.base == X86_REG_RIP and o1.reg == dstreg:
                            G = ni.address + ni.size + o0.mem.disp
                            hooks[G] = (mem.disp, ins.address)
                            break

print(f"hooks stored: {len(hooks)}  labels stored: {len(labels)}")

# pair by nearest global slot within 0x40
pairs = []
for gh, (rva, ha) in hooks.items():
    best = None
    for gl, (s, la) in labels.items():
        d = abs(gl - gh)
        if d <= 0x40:
            if best is None or d < best[0]:
                best = (d, gl, s)
    if best:
        pairs.append((best[2], rva, gh, best[1]))

pairs.sort(key=lambda p: p[2])
print(f"\n=== {len(pairs)} pairs (by hook global slot) ===")
for s, rva, gh, gl in pairs:
    print(f"  G={gh:#x} rva={rva:#010x} labelG={gl:#x}  {s}")

import json
with open(r"d:\9-4#2\xxx\analysis\rva_labels.json", "w") as f:
    json.dump([{"label": s, "old_rva": rva, "hook_slot": gh, "label_slot": gl} for s, rva, gh, gl in pairs], f, indent=1)
print("saved rva_labels.json")
