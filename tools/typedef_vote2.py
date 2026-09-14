# typedef_vote2.py - proper length-prefixed string harvest; backref first-char offsets; vote table
import struct, collections

META = r"C:\冒险岛online\mxdclassic\Maplestory_Classic_Data\il2cpp_data\Metadata\global-metadata.dat"
data = open(META, "rb").read()
fsize = len(data)

P12_OFF, P12_SIZE = 0xa57e38, 0x12b040
P3_OFF, P3_END = 0xc9e60, 0x597eb7
zone = data[P12_OFF:P12_OFF+P12_SIZE]

# harvest [len][chars][NUL] records; name offset = position of first char (heap-relative)
strings = []  # (reloff, text)
for p in range(len(zone) - 4):
    L = zone[p]
    if 2 <= L <= 120:
        chunk = zone[p+1:p+1+L]
        if len(chunk) == L and zone[p+1+L] == 0 and all(32 <= b < 127 for b in chunk):
            strings.append((p + 1, chunk.decode()))
print(f"length-prefixed strings: {len(strings)}")
with_pipe = [s for s in strings if "|" in s[1]]
print(f"with '|' (ns|name): {len(with_pipe)}")

# sanity: check VecCtrlMob present
for off, t in strings:
    if "VecCtrlMob" in t:
        print(f"  check: @{off:#x} {t!r}")

# backref for names with '|' (typedef-style), sample up to 400
sample = with_pipe[::max(1, len(with_pipe)//400)][:400]
def backrefs(reloff):
    needle = struct.pack("<I", reloff)
    out = []
    s = 0
    while True:
        i = data.find(needle, s)
        if i < 0:
            break
        if not (P12_OFF <= i < P12_OFF+P12_SIZE) and not (P3_OFF <= i < P3_END):
            out.append(i)
        s = i + 1
    return out

allhits = []
for reloff, nm in sample:
    hs = backrefs(reloff)
    for h in hs:
        allhits.append((h, nm, reloff))
print(f"\ntotal backref hits: {len(allhits)} from {len(sample)} names")

allhits.sort()
# cluster by proximity
clusters = []
cur = []
last = None
for h, nm, ro in allhits:
    if last is not None and h - last > 0x20000:
        clusters.append(cur)
        cur = []
    cur.append((h, nm, ro))
    last = h
if cur:
    clusters.append(cur)
clusters.sort(key=len, reverse=True)
print(f"\n=== top clusters ===")
for c in clusters[:8]:
    lo, hi = c[0][0], c[-1][0]
    print(f"  [{lo:#x}..{hi:#x}] n={len(c)} span={hi-lo:#x}")
    for h, nm, ro in c[:6]:
        print(f"     @{h:#x} off={ro:#x} {nm}")

# for the top cluster, find consistent stride: for each candidate stride, count hits at (base + k*stride + foff)
if clusters:
    big = clusters[0]
    poss = sorted(set(h for h, _, _ in big))
    best = None
    for stride in range(0x10, 0xa0, 4):
        for foff in range(0, stride, 4):
            base = poss[0] - foff
            cnt = sum(1 for p in poss if (p - base) % stride == 0)
            if best is None or cnt > best[0]:
                best = (cnt, stride, foff)
    cnt, stride, foff = best
    print(f"\nbest fit: {cnt}/{len(poss)} hits at stride {stride:#x} foff {foff:#x}")
