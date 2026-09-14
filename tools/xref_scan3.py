# xref_scan3.py - filtered blind scan over whole dump
import struct

BIN = r"d:\9-4#2\xxx\analysis\memscan\region_0_0x269C000.bin"
BASE = 0x180000000
RUNBASE = 0x269C000  # region base in ControlProc when dumped
data = open(BIN, "rb").read()
n = len(data)

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
    0x15bfb8: "str_il2cpp_metadata", 0x161018: "str_build_2026-07-18",
    0x181b98: "lbl_meta_ord10", 0x181bc0: "lbl_meta_ord13", 0x181be8: "lbl_meta_verified",
    0x181ac0: "lbl_runtime_dump_0902", 0x181b78: "lbl_runtimefull_0902",
}
tset = set(targets)

print("=== rip-relative (|disp|>=0x100), whole dump ===")
found = []
for p in range(0x1000, n - 8):
    for k in (2, 3, 4):
        disp = struct.unpack_from("<i", data, p + k)[0]
        if -0x100 < disp < 0x100:
            continue
        t = p + k + 4 + disp
        if t in tset:
            found.append((p, k, t))
            break
for p, k, t in found:
    print(f"  @{p:#x} (k={k}) -> {t:#x} {targets[t]}")
print(f"total: {len(found)}")

print("\n=== dword RVA refs to targets ===")
dhits = {}
for off in range(0, n - 4, 4):
    v = struct.unpack_from("<I", data, off)[0]
    if v in tset:
        dhits.setdefault(v, []).append(off)
for v, offs in sorted(dhits.items()):
    print(f"  {targets[v]} @{v:#x}: {len(offs)} at {[hex(o) for o in offs[:10]]}")

print("\n=== imm64 refs (mov r64,imm64 = 48 b8-bf) ===")
for off in range(0x1000, n - 10):
    if data[off] == 0x48 and 0xB8 <= data[off+1] <= 0xBF:
        v = struct.unpack_from("<Q", data, off+2)[0]
        t = v - BASE
        if t in tset:
            print(f"  @{off:#x} mov imm64 -> {t:#x} {targets[t]} (BASE)")
        t2 = v - RUNBASE
        if t2 in tset:
            print(f"  @{off:#x} mov imm64 -> {t2:#x} {targets[t2]} (RUNBASE)")

print("\n=== qword refs with RUNBASE ===")
for off in range(0, n - 8, 8):
    v = struct.unpack_from("<Q", data, off)[0] - RUNBASE
    if v in tset:
        print(f"  @{off:#x} -> {v:#x} {targets[v]}")
