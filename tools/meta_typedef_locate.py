# meta_typedef_locate.py - locate typedef table via VecCtrlMob nameIndex backreference
import struct

META = r"C:\冒险岛online\mxdclassic\Maplestory_Classic_Data\il2cpp_data\Metadata\global-metadata.dat"
data = open(META, "rb").read()
pairs = []
for i in range(40):
    o, s = struct.unpack_from("<ii", data, 8 + i * 8)
    pairs.append((o, s))
o12, s12 = pairs[12]

# find name offset inside pair12 (nameIndex convention: offset of length-prefixed entry start)
name = b"Msc.Game.Object.Control|VecCtrlMob"
pos = data.find(name, o12, o12 + s12)
print(f"name content at file {pos:#x}, rel to pair12: {pos-o12:#x}")
# entry start = 1 byte before (length prefix)
entry_rel = pos - 1 - o12
print(f"entry start rel = {entry_rel:#x}, length byte = {data[pos-1]:#x} (name len {len(name)})")

for cand in (entry_rel, pos - o12):
    needle = struct.pack("<i", cand)
    hits = []
    start = 0
    while len(hits) < 300:
        idx = data.find(needle, start)
        if idx < 0:
            break
        hits.append(idx)
        start = idx + 1
    from collections import Counter
    def region_of(off):
        for i, (o, s) in enumerate(pairs):
            if o <= off < o + s:
                return i
        return -1
    cnt = Counter(region_of(h) for h in hits)
    print(f"\nnameIndex candidate {cand:#x}: {len(hits)} hits, by pair: {dict(cnt)}")
    # show context of first few hits inside plausible table regions
    for h in hits[:8]:
        ctx = data[h-16:h+48]
        print(f"  @{h:#x} (pair{region_of(h)}): {ctx.hex(' ')}")
