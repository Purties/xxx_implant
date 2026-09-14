# parse_methods.py - confirm methods table: best (pair, stride, nameIndex field offset)
# validated by nameIndex -> pair3 NUL-terminated string hit rate
import struct

META = r"C:\冒险岛online\mxdclassic\Maplestory_Classic_Data\il2cpp_data\Metadata\global-metadata.dat"
data = open(META, "rb").read()
fsize = len(data)
raw = [struct.unpack_from("<ii", data, 8 + i*8) for i in range(40)]
pairs = []
for i, (o, s) in enumerate(raw):
    if o < 0 or s <= 0 or o >= fsize:
        pairs.append((0, 0))
        continue
    pairs.append((o, min(s, fsize - o)))
o3, s3 = pairs[3]
print(f"pair3 string table: off {o3:#x} size {s3:#x}")

def name_at(idx):
    if 0 <= idx < s3:
        end = data.find(b"\x00", o3+idx, o3+idx+256)
        if 0 < end <= o3+s3:
            s = data[o3+idx:end]
            if s and all(32 <= b < 127 or b >= 0x80 for b in s):
                return s.decode("utf-8", "replace")
    return None

results = []
for pi, (o, s) in enumerate(pairs):
    if s < 0x1000:
        continue
    for stride in (0x18, 0x1c, 0x20, 0x24, 0x28, 0x2c, 0x30):
        total = s // stride
        if total < 1000:
            continue
        for foff in (0, 4, 8):
            # sample up to 4000 evenly spaced records
            step = max(1, total // 4000)
            idxs = range(0, total, step)
            valid = 0
            checked = 0
            for i in idxs:
                ni = struct.unpack_from("<i", data, o + i*stride + foff)[0]
                if 0 <= ni < s3 and name_at(ni):
                    valid += 1
                checked += 1
            rate = valid / checked if checked else 0
            if rate > 0.5:
                results.append((rate, pi, stride, foff, total))

results.sort(reverse=True)
print("\n=== candidates (rate>0.5), top 12 ===")
for rate, pi, stride, foff, total in results[:12]:
    print(f"  pair{pi} stride={stride:#x} nameOff=+{foff:#x} rate={rate:.2%} records={total}")

if results:
    rate, pi, stride, foff, total = results[0]
    o, s = pairs[pi]
    print(f"\n=== best: pair{pi} off {o:#x} stride {stride:#x} nameOff +{foff:#x} ===")
    for i in range(10):
        rec = o + i*stride
        nf = struct.unpack_from("<I", data, rec + foff)[0]
        dwords = struct.unpack_from(f"<{stride//4}I", data, rec)
        print(f"  [{i}] name={name_at(nf)!r:30s}  " + " ".join(f"{d:#x}" for d in dwords[:8]))
