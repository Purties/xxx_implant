# typedef_density.py - density map: dwords that are valid pair12 name offsets, per 0x800 window
import struct

META = r"C:\冒险岛online\mxdclassic\Maplestory_Classic_Data\il2cpp_data\Metadata\global-metadata.dat"
data = open(META, "rb").read()
fsize = len(data)

P12_OFF, P12_SIZE = 0xa57e38, 0x12b040
P3_OFF, P3_END = 0xc9e60, 0x597eb7
zone = data[P12_OFF:P12_OFF+P12_SIZE]

# valid name offsets: strict [len][chars][NUL]
valid = bytearray(P12_SIZE + 130)
cnt = 0
for p in range(len(zone) - 126):
    L = zone[p]
    if 2 <= L <= 120 and p + 1 + L < len(zone):
        if zone[p+1+L] == 0 and all(32 <= b < 127 for b in zone[p+1:p+1+L]):
            valid[p+1] = 1
            cnt += 1
print(f"valid name offsets: {cnt}")

# also plain NUL-terminated strings (no length byte requirement): offset set where a "word char" follows a NUL
valid2 = bytearray(P12_SIZE + 2)
cnt2 = 0
for p in range(1, len(zone)-1):
    if zone[p-1] == 0 and 65 <= zone[p] <= 122:  # letter start after NUL
        valid2[p] = 1
        cnt2 += 1
print(f"NUL-led word starts: {cnt2}")

WIN = 0x800
def density_map(validset, label):
    rows = []
    nw = fsize // WIN
    for w in range(nw):
        o = w * WIN
        if (P12_OFF <= o < P12_OFF + P12_SIZE) or (P3_OFF <= o < P3_END):
            continue
        n4 = WIN // 4
        vals = struct.unpack_from(f"<{n4}I", data, o)
        c = 0
        for v in vals:
            if 0 <= v < P12_SIZE and validset[v]:
                c += 1
        if c >= 30:
            rows.append((o, c))
    # merge consecutive windows
    merged = []
    for o, c in rows:
        if merged and o - merged[-1][1] <= WIN * 2:
            merged[-1][1] = o
            merged[-1][2] += c
        else:
            merged.append([o, o, c])
    print(f"\n=== density map {label} (threshold 30/{WIN}) ===")
    for start, last, tot in merged:
        print(f"  [{start:#x} .. {last+WIN:#x}]  hits={tot}  span={last+WIN-start:#x}")
    return merged

m1 = density_map(valid, "len-prefixed")
m2 = density_map(valid2, "nul-led")
