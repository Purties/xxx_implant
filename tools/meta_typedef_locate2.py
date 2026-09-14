# meta_typedef_locate2.py - find VecCtrlMob in main string table (pair3), backref to typedef table
import struct
from collections import Counter

META = r"C:\冒险岛online\mxdclassic\Maplestory_Classic_Data\il2cpp_data\Metadata\global-metadata.dat"
data = open(META, "rb").read()
pairs = []
for i in range(40):
    o, s = struct.unpack_from("<ii", data, 8 + i * 8)
    pairs.append((o, s))

def region_of(off):
    for i, (o, s) in enumerate(pairs):
        if o <= off < o + s:
            return i
    return -1

o3, s3 = pairs[3]
pos = data.find(b"VecCtrlMob\x00", o3, o3 + s3)
print(f"'VecCtrlMob' in pair3 at file {pos:#x}, rel {pos-o3:#x}")

name_index = pos - o3
needle = struct.pack("<i", name_index)
hits = []
start = 0
while len(hits) < 2000:
    idx = data.find(needle, start)
    if idx < 0:
        break
    hits.append(idx)
    start = idx + 1
cnt = Counter(region_of(h) for h in hits)
print(f"nameIndex {name_index:#x}: {len(hits)} hits, by pair: {dict(sorted(cnt.items()))}")

# Inspect candidate typedef-table regions: pick hits whose region has many hits
for pair_idx, n in cnt.most_common(5):
    o, s = pairs[pair_idx]
    sub = [h for h in hits if region_of(h) == pair_idx]
    print(f"\npair{pair_idx} ({o:#x}+{s:#x}): {n} hits")
    for h in sub[:6]:
        ctx = data[h-8:h+56]
        print(f"  @{h:#x}: {ctx.hex(' ')}")
