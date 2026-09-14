# dump_vtable_rows.py - decode version table rows + sig blobs from injected DLL dump
# dump base assumption: image base 0x180000000, file offset == RVA
import struct, sys

BIN = r"d:\9-4#2\xxx\analysis\memscan\region_0_0x269C000.bin"
data = open(BIN, "rb").read()
print(f"dump size: {len(data):#x}")

def hx(off, n, width=16):
    out = []
    for i in range(0, n, width):
        chunk = data[off+i:off+i+width]
        hexs = " ".join(f"{b:02x}" for b in chunk)
        asc = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        out.append(f"@{off+i:#x}  {hexs:<{width*3}} {asc}")
    return "\n".join(out)

def qwords(off, n):
    return [struct.unpack_from("<Q", data, off + i*8)[0] for i in range(n)]

# --- 1. verify base: qwords @0x184150 should be 0x1801857xx
print("\n=== ptr array @0x184150 (expect 0x1801857xx) ===")
ptrs = qwords(0x184150, 5)
for i, p in enumerate(ptrs):
    print(f"  [{i}] {p:#x}  -> file off {p-0x180000000:#x}" if p >= 0x180000000 else f"  [{i}] {p:#x} (raw)")

# --- 2. dump 5 rows x 0x40 at 0x185780
print("\n=== version rows @0x185780, 5 x 0x40 ===")
for r in range(5):
    ro = 0x185780 + r*0x40
    vals = struct.unpack_from("<16I", data, ro)
    print(f"row{r} @{ro:#x}: " + " ".join(f"{v:#x}" for v in vals))

# --- 3. second ptr array @0x184190
print("\n=== ptr array2 @0x184190 ===")
ptrs2 = qwords(0x184190, 5)
for i, p in enumerate(ptrs2):
    print(f"  [{i}] {p:#x}")

# --- 4. dwords @0x1841b8
print("\n=== dwords @0x1841b0..0x1841d0 ===")
print(hx(0x1841b0, 0x20))

# --- 5. blobs at ptrs2 targets (as raw offsets)
print("\n=== blob heads ===")
for i, p in enumerate(ptrs2):
    if p < len(data):
        print(f"-- blob{i} @{p:#x}")
        print(hx(p, 0x60))

# --- 6. scan for known RVA dwords anywhere in dump
known = {
    0x6DDFD0:  "8/27 V",
    0x102E640: "9/4 V",
    0x102E670: "9/4 I",
    0x102EF10: "9/4 D",
    0x11BE640: "9/13 V",
    0x11BE670: "9/13 I",
    0x11BEF10: "9/13 D",
    0x1049B70: "9/13 SetDamaged",
    0x1660650: "9/13 Update",
}
print("\n=== dword occurrences of known RVAs (offset, then 4 qwords ctx) ===")
for val, tag in known.items():
    needle = struct.pack("<I", val)
    hits = []
    s = 0
    while True:
        i = data.find(needle, s)
        if i < 0: break
        hits.append(i)
        s = i + 1
    print(f"{tag} {val:#x}: {len(hits)} hits at {[hex(h) for h in hits[:20]]}")

# --- 7. hashes context: confirm 5 hash entries and look for a 6th slot
print("\n=== hash table region @0x183fa0..0x184150 ===")
print(hx(0x183fa0, 0x1b0))
