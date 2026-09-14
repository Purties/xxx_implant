# vrow_hunt.py - find where version-row RVA values are stored in the DLL dump
import struct

DUMP = r"d:\9-4#2\xxx\analysis\memscan\region_0_0x269C000.bin"
data = open(DUMP, "rb").read()

# known row RVAs (V values per row) and full 9/13 effective row
MARKERS = {
    "8/27 V": 0x6ddfd0,
    "9/4 V": 0x102e640,
    "9/13 V": 0x11be640,
    "9/13 I": 0x11be670,
    "9/13 D": 0x11bef10,
    "9/13 SetDamaged": 0x1049b70,
    "9/13 Update": 0x1660650,
}
for name, v in MARKERS.items():
    b32 = struct.pack("<I", v)
    b64 = struct.pack("<Q", v)
    hits32 = []
    s = 0
    while True:
        i = data.find(b32, s)
        if i < 0:
            break
        hits32.append(i)
        s = i + 1
    print(f"{name} {v:#x}: u32 hits {[hex(h) for h in hits32[:20]]}{' ...' if len(hits32)>20 else ''} (n={len(hits32)})")
