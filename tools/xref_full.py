# xref_full.py - 1) qword pointer scan for BASE+target  2) linear disasm code range, collect rip-relative refs to targets
import struct
from capstone import Cs, CsInsn, CS_ARCH_X86, CS_MODE_64

BIN = r"d:\9-4#2\xxx\analysis\memscan\region_0_0x269C000.bin"
BASE = 0x180000000
data = open(BIN, "rb").read()

targets = {
    0x183fc0: "hash[0]", 0x184150: "rowPtrArray", 0x184190: "blobPtrArray", 0x1841b8: "dwordArray_231",
    0x181c08: "lbl_typedef1514_m3", 0x181ca0: "lbl_typedef1514_m2", 0x181cd0: "lbl_typedef1514_m19",
    0x181d00: "lbl_typedef1514_m4", 0x181d30: "lbl_typedef1514_m15", 0x181c38: "lbl_typedef1514_m5",
    0x181c68: "lbl_typedef1514_m6_op312",
    0x181b50: "lbl_ordinal31_combat", 0x181a88: "lbl_rva+metadata", 0x1831d8: "lbl_dump11_rva",
    0x1831e8: "lbl_exact_11BEF10", 0x183208: "lbl_exact_11BE640",
    0x1815f8: "str_il2cpp_class_get_method_from_name", 0x181620: "str_il2cpp_class_get_methods",
    0x168ba0: "str_update_rejected", 0x168a28: "str_SetVelocity", 0x168a38: "str_DoCombatStep",
    0x168a48: "str_SetImpactNext", 0x168a58: "str_SetDamaged", 0x183fa0: "str_GameAssembly.dll",
    0x15bfb8: "str_il2cpp_metadata",
}

# --- qword pointer scan
print("=== qword pointer scan (BASE+target) ===")
qw_hits = {t: [] for t in targets}
for off in range(0, len(data) - 8, 8):
    v = struct.unpack_from("<Q", data, off)[0]
    t = v - BASE
    if t in qw_hits:
        qw_hits[t].append(off)
for t, name in targets.items():
    if qw_hits[t]:
        print(f"  {name} @{t:#x}: qword refs at {[hex(h) for h in qw_hits[t][:8]]}")

# --- rip-relative scan via linear disasm with skipdata
print("\n=== rip-relative refs in code (linear disasm, skipdata) ===")
md = Cs(CS_ARCH_X86, CS_MODE_64)
md.skipdata = True
md.detail = True
rip_hits = {t: [] for t in targets}
CODE_START, CODE_END = 0x1000, 0x160000
chunk = data[CODE_START:CODE_END]
count = 0
for ins in md.disasm(chunk, BASE + CODE_START):
    count += 1
    if ins.id == 0:
        continue
    for op in ins.operands:
        if op.type == 2:  # MEM
            if op.mem.base == 41:  # rip
                tgt = (ins.address + ins.size + op.mem.disp) & 0xFFFFFFFFFFFFFFFF
                t = tgt - BASE
                if t in rip_hits:
                    rip_hits[t].append((ins.address - BASE, ins.mnemonic, ins.op_str))
print(f"instructions decoded: {count}")
for t, name in targets.items():
    if rip_hits[t]:
        print(f"  {name} @{t:#x}:")
        for a, m, o in rip_hits[t][:10]:
            print(f"    @{a:#x}: {m} {o}")
