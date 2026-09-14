# typedef_vote.py - mass backreference of type names; vote on (phase, stride) consistency
import struct, collections

META = r"C:\冒险岛online\mxdclassic\Maplestory_Classic_Data\il2cpp_data\Metadata\global-metadata.dat"
data = open(META, "rb").read()
fsize = len(data)

P12_OFF, P12_SIZE = 0xa57e38, 0x12b040
P3_OFF, P3_END = 0xc9e60, 0x597eb7

# harvest a broad set of type names: take strings in the "types zone" of pair12
# heuristic: strings 3..40 chars, printable, no spaces, not ending .cs
zone = data[P12_OFF:P12_OFF+P12_SIZE]
strings = []
pos = 0
while pos < len(zone):
    end = zone.find(b"\x00", pos)
    if end < 0:
        break
    s = zone[pos:end]
    if 3 <= len(s) <= 40 and all(32 <= b < 127 for b in s) and b" " not in s and not s.endswith(b".cs"):
        strings.append((pos, s.decode()))
    pos = end + 1
print(f"harvested {len(strings)} candidate type strings")

# pick a sample spread across the alphabet
sample = strings[::max(1, len(strings)//300)][:300]

# for each name, find dword backrefs outside heaps
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

allhits = []  # (pos, name)
for reloff, nm in sample:
    for h in backrefs(reloff):
        allhits.append((h, nm))
print(f"total backref hits: {len(allhits)}")

# cluster hits by region: sort, group gaps > 0x1000
allhits.sort()
clusters = []
cur = [allhits[0]]
for h, nm in allhits[1:]:
    if h - cur[-1][0] > 0x10000:
        clusters.append(cur)
        cur = []
    cur.append((h, nm))
clusters.append(cur)
print(f"\n=== clusters ({len(clusters)}) ===")
for c in clusters:
    lo, hi = c[0][0], c[-1][0]
    phases = collections.Counter(p % 4 for p, _ in c)
    print(f"  [{lo:#x}..{hi:#x}] n={len(c)} span={hi-lo:#x} phases={dict(phases)}")
    names = [nm for _, nm in c]
    print(f"    names: {names[:14]}")

# for the biggest cluster, test strides
if clusters:
    big = max(clusters, key=len)
    pos = sorted(p for p, _ in big)
    print(f"\nbiggest cluster [{big[0][0]:#x}..{big[-1][0]:#x}] n={len(pos)}")
    deltas = collections.Counter()
    for i in range(len(pos)-1):
        d = pos[i+1] - pos[i]
        if 0 < d <= 0x400:
            deltas[d] += 1
    print("top small deltas:", deltas.most_common(12))
