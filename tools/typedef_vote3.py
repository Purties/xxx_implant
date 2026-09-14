# typedef_vote3.py - backref FULL-FORM name offsets (large, non-round), density clustering
import struct, collections

META = r"C:\冒险岛online\mxdclassic\Maplestory_Classic_Data\il2cpp_data\Metadata\global-metadata.dat"
data = open(META, "rb").read()
fsize = len(data)

P12_OFF, P12_SIZE = 0xa57e38, 0x12b040
P3_OFF, P3_END = 0xc9e60, 0x597eb7
zone = data[P12_OFF:P12_OFF+P12_SIZE]

strings = []
for p in range(len(zone) - 126):
    L = zone[p]
    if 2 <= L <= 120 and p + 1 + L < len(zone):
        if zone[p+1+L] == 0 and all(32 <= b < 127 for b in zone[p+1:p+1+L]):
            strings.append((p + 1, zone[p+1:p+1+L].decode()))
with_pipe = [(o, t) for o, t in strings if "|" in t]
print(f"'|' names: {len(with_pipe)}")

# keep offsets unlikely to coincide: >= 0x8000 and not ending in 0x00
cand = [(o, t) for o, t in with_pipe if o >= 0x8000 and (o & 0xff) != 0]
print(f"after coincidence filter: {len(cand)}")

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
for reloff, nm in cand:
    for h in backrefs(reloff):
        allhits.append((h, nm, reloff))
print(f"total hits: {len(allhits)}")

# density histogram, bin 0x400
hist = collections.Counter(h // 0x400 for h, _, _ in allhits)
hot = sorted(((c, b) for b, c in hist.items() if c >= 3), reverse=True)
print(f"\nhot bins (>=3 hits per 0x400): {len(hot)}")
for c, b in hot[:25]:
    names = [nm for h, nm, _ in allhits if h // 0x400 == b][:5]
    print(f"  bin @{b*0x400:#x}: {c} hits  e.g. {names}")
