# row_extract.py - extract active RVA row from dispatch stencil (lea r64,[r64+disp32] with large disp)
import struct

BIN = r"d:\9-4#2\xxx\analysis\memscan\region_0_0x269C000.bin"
data = open(BIN, "rb").read()

REG = ["rax","rcx","rdx","rbx","rsp","rbp","rsi","rdi","r8","r9","r10","r11","r12","r13","r14","r15"]

# scan a generous window for the stencil: REX.W(48/4c) 8d modrm(mod=10 rm!=100/101) disp32
print("=== lea r64,[r64+disp32] in 0x126000..0x12a000, disp>=0x10000 ===")
rows = []
for p in range(0x126000, 0x12a000 - 7):
    if data[p] in (0x48, 0x4C) and data[p+1] == 0x8D:
        modrm = data[p+2]
        mod, reg, rm = (modrm >> 6) & 3, (modrm >> 3) & 7, modrm & 7
        if mod == 2 and rm != 4:  # disp32 form, no SIB
            disp = struct.unpack_from("<i", data, p+3)[0]
            if disp >= 0x10000:
                r16 = reg + (8 if data[p] == 0x4C else 0)
                b16 = rm
                rows.append((p, REG[r16], REG[b16], disp))
for p, rd, rb, disp in rows:
    print(f"  @{p:#x}: lea {rd}, [{rb} + {disp:#x}]   (GameAssembly+{disp:#x})")
print(f"total: {len(rows)}")
print("\n=== distinct disp values in order ===")
seen = []
for _, _, _, d in rows:
    if d not in seen:
        seen.append(d)
for i, d in enumerate(seen):
    print(f"  [{i:2}] {d:#x}")
