# meta_typedef_hunt.py - locate typedef table in v39 metadata via string-offset backreference
import struct

META = r"C:\冒险岛online\mxdclassic\Maplestory_Classic_Data\il2cpp_data\Metadata\global-metadata.dat"
data = open(META, "rb").read()

pairs = []
for i in range(40):
    o, s = struct.unpack_from("<ii", data, 8 + i * 8)
    pairs.append((o, s))

# pair3: suspected main string table
o3, s3 = pairs[3]
print(f"pair3 region {o3:#x}..{o3+s3:#x}")
print("pair3 head bytes:", data[o3:o3+96])

# find offset of a known type-name string inside pair3 region
needle = b"Msc.Game|MapObject\x00"
pos = data.find(needle, o3, o3 + s3)
print(f"'{needle[:-1].decode()}' found at file offset {pos:#x}",)
if pos >= 0:
    name_index = pos - o3  # offset relative to string table start
    print(f"  relative nameIndex = {name_index:#x} ({name_index})")
    # search whole file for int32 == name_index (little endian) -> candidate typedef records
    needle4 = struct.pack("<i", name_index)
    hits = []
    start = 0
    while True:
        idx = data.find(needle4, start)
        if idx < 0 or len(hits) > 200:
            break
        hits.append(idx)
        start = idx + 1
    # filter: inside which pair region?
    def region_of(off):
        for i, (o, s) in enumerate(pairs):
            if o <= off < o + s:
                return i
        return -1
    from collections import Counter
    cnt = Counter(region_of(h) for h in hits)
    print(f"  int32 backrefs: {len(hits)} hits; by pair region: {dict(cnt)}")
