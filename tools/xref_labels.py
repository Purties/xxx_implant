# xref_labels.py - find RIP-relative lea references to key data offsets, disasm context
import struct
from capstone import Cs, CS_ARCH_X86, CS_MODE_64

BIN = r"d:\9-4#2\xxx\analysis\memscan\region_0_0x269C000.bin"
BASE = 0x180000000
data = open(BIN, "rb").read()
md = Cs(CS_ARCH_X86, CS_MODE_64)

targets = {
    0x183fc0: "hash[0]",
    0x184150: "rowPtrArray",
    0x184190: "blobPtrArray",
    0x1841b8: "dwordArray_231",
    0x181c08: "lbl_typedef1514_m3",
    0x181ca0: "lbl_typedef1514_m2",
    0x181b50: "lbl_ordinal31_combat",
    0x181a88: "lbl_rva+metadata",
    0x1831d8: "lbl_dump11_rva",
    0x1831e8: "lbl_exact_11BEF10",
    0x183208: "lbl_exact_11BE640",
    0x1815f8: "str_il2cpp_class_get_method_from_name",
    0x181620: "str_il2cpp_class_get_methods",
    0x168ba0: "str_update_rejected",
    0x168a28: "str_SetVelocity",
    0x168a58: "str_SetDamaged",
    0x183fa0: "str_GameAssembly.dll",
}

# scan for lea r64, [rip+disp32]: (48|4c|4d) 8d modrm(mod=00,rm=101)
hits = {t: [] for t in targets}
i = 0
end = len(data) - 7
while i < end:
    b0 = data[i]
    if b0 in (0x48, 0x4C, 0x4D) and data[i+1] == 0x8D:
        modrm = data[i+2]
        if (modrm & 0xC7) == 0x05:
            disp = struct.unpack_from("<i", data, i+3)[0]
            tgt = (BASE + i + 7 + disp) & 0xFFFFFFFFFFFFFFFF
            off = tgt - BASE
            if off in hits:
                hits[off].append(i)
    i += 1

for t, name in targets.items():
    hs = hits[t]
    print(f"{name} @{t:#x}: {len(hs)} xrefs {[hex(h) for h in hs[:12]]}")

# disasm window helper
def disasm(off, n, note=""):
    print(f"\n--- disasm @{off:#x} {note} ---")
    code = data[off:off+n]
    for ins in md.disasm(code, BASE + off):
        print(f"  {ins.address-BASE:#x}: {ins.mnemonic} {ins.op_str}")

# disasm around each xref hit (first hit per target, -0x20..+0x60)
for t, name in targets.items():
    if hits[t]:
        h = hits[t][0]
        disasm(max(0, h-0x30), 0x90, f"around xref to {name}")
