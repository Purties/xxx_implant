# anchor_dwords.py - find where pair3 name offsets appear as dwords in the metadata file
import struct, collections

META = r"C:\冒险岛online\mxdclassic\Maplestory_Classic_Data\il2cpp_data\Metadata\global-metadata.dat"
data = open(META, "rb").read()
pairs = [struct.unpack_from("<ii", data, 8 + i*8) for i in range(40)]

anchors = {"Update": 20267, "Awake": 247, ".ctor": 113, "Start": 11898, "Dispose": 85492}

def pair_of(off):
    for i, (o, s) in enumerate(pairs):
        if o <= off < o + s:
            return i
    return -1

for nm, val in anchors.items():
    needle = struct.pack("<I", val)
    hits = []
    s = 0
    while True:
        i = data.find(needle, s)
        if i < 0 or len(hits) >= 100000:
            break
        hits.append(i)
        s = i + 4
    cnt = collections.Counter(pair_of(h) for h in hits)
    print(f"{nm} ({val}): {len(hits)} dword hits; by pair: {dict(sorted(cnt.items(), key=lambda x: -x[1])[:8])}")
    # show stride regularity in top pair
    if cnt:
        top_pair, _ = cnt.most_common(1)[0]
        po, ps = pairs[top_pair]
        inpair = sorted(h - po for h in hits if pair_of(h) == top_pair)
        if len(inpair) >= 4:
            diffs = collections.Counter()
            for a, b in zip(inpair, inpair[1:]):
                d = b - a
                for stride in (0x14, 0x18, 0x1c, 0x20, 0x24, 0x28, 0x2c, 0x30, 0x34, 0x38, 0x40, 0x48, 0x50, 0x58, 0x60):
                    if d % stride == 0:
                        diffs[stride] += 1
            print(f"   top pair{top_pair}: {len(inpair)} hits, first rels: {[hex(x) for x in inpair[:8]]}, stride-compat: {dict(diffs.most_common(5))}")
