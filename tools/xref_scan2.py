# xref_scan2.py - blind scan: all rip-relative forms (k=2,3,4) + qword base inference
import struct
from collections import Counter

BIN = r"d:\9-4#2\xxx\analysis\memscan\region_0_0x269C000.bin"
BASE = 0x180000000
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
}
tset = set(targets)

print("=== blind rip-relative scan (disp at +2/+3/+4) ===")
found = []
for p in range(0x1000, n - 8):
    for k in (2, 3, 4):
        disp = struct.unpack_from("<i", data, p + k)[0]
        t = p + k + 4 + disp
        if t in tset:
            found.append((p, k, t))
            break
for p, k, t in found:
    print(f"  @{p:#x} (k={k}) -> {t:#x} {targets[t]}")
print(f"total: {len(found)}")

print("\n=== qword base inference ===")
bases = Counter()
for off in range(0, n - 8, 8):
    v = struct.unpack_from("<Q", data, off)[0]
    for t in tset:
        b = v - t
        if 0 <= b <= 0x7FFFFFFFFFFF:
            bases[b] += 1
for b, c in bases.most_common(8):
    print(f"  base {b:#x}: {c} target-hits")

print("\n=== qword refs with inferred bases ===")
for base_guess, cnt in bases.most_common(3):
    if cnt < 2:
        continue
    hits = []
    for off in range(0, n - 8, 8):
        v = struct.unpack_from("<Q", data, off)[0] - base_guess
        if v in tset:
            hits.append((off, v))
    print(f" base {base_guess:#x}: {len(hits)} refs")
    for off, v in hits[:24]:
        print(f"   @{off:#x} -> {v:#x} {targets[v]}")
