# typedef_analyze.py - validate typedef table at stride 0x4c anchored on VecCtrlMob hit
# field-role discovery: nameIndex fields (valid pair12 name offsets), monotonic fields (*Start)
import struct

META = r"C:\冒险岛online\mxdclassic\Maplestory_Classic_Data\il2cpp_data\Metadata\global-metadata.dat"
data = open(META, "rb").read()

P12_OFF, P12_SIZE = 0xa57e38, 0x12b040
zone = data[P12_OFF:P12_OFF+P12_SIZE]

# build set of valid name offsets (first-char positions of [len][chars][NUL] records)
valid_name_off = set()
for p in range(len(zone) - 126):
    L = zone[p]
    if 2 <= L <= 120 and p + 1 + L < len(zone):
        if zone[p+1+L] == 0 and all(32 <= b < 127 for b in zone[p+1:p+1+L]):
            valid_name_off.add(p + 1)
print(f"valid name offsets: {len(valid_name_off)}")

ANCHOR = 0xfb99a0   # VecCtrlMob nameOff hit
STRIDE = 0x4c
NDW = STRIDE // 4   # 19 dwords

def rec_fields(k):
    """record k relative to anchor; nameOff field at record+8 (observed f2 == hit pos => record start = hit-8)"""
    base = ANCHOR - 8 + k * STRIDE
    if base < 0 or base + STRIDE > len(data):
        return None
    return struct.unpack_from(f"<{NDW}I", data, base)

K = 3000
# name-index hit rate per field position
name_hits = [0]*NDW
monotonic = [True]*NDW
prev = [None]*NDW
mono_count = [0]*NDW
total = 0
neg1 = [0]*NDW
for k in range(-K, K):
    f = rec_fields(k)
    if f is None:
        continue
    total += 1
    for i, v in enumerate(f):
        if v in valid_name_off:
            name_hits[i] += 1
        if v == 0xFFFFFFFF:
            neg1[i] += 1
        if prev[i] is not None and v >= prev[i] and v != 0xFFFFFFFF and prev[i] != 0xFFFFFFFF:
            mono_count[i] += 1
    for i, v in enumerate(f):
        prev[i] = v

print(f"\nrecords analyzed: {total}  (stride {STRIDE:#x})")
print(f"{'field':>5} {'nameHit%':>9} {'monoInc%':>9} {'neg1%':>7}")
for i in range(NDW):
    nh = name_hits[i]/total*100
    mc = mono_count[i]/max(1,total-1)*100
    n1 = neg1[i]/total*100
    mark = ""
    if nh > 50: mark += " <NAME>"
    if mc > 90: mark += " <MONO>"
    if n1 > 80: mark += " <MOSTLY-1>"
    print(f"  f{i:02d} {nh:8.1f}% {mc:8.1f}% {n1:6.1f}%{mark}")

# show a few records around anchor
print("\n=== records near anchor ===")
for k in (-2, -1, 0, 1, 2):
    f = rec_fields(k)
    nm = None
    for i, v in enumerate(f):
        if v in valid_name_off:
            L = zone[v-1]
            nm = (i, zone[v:v+L].decode())
    print(f"  k={k}: name={nm}")
    print("        " + " ".join(f"{v:#x}" for v in f))
