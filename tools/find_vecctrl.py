# find_vecctrl.py - locate 'VecCtrlMob' anywhere in metadata; dump surrounding strings; show pair layout
import struct

META = r"C:\冒险岛online\mxdclassic\Maplestory_Classic_Data\il2cpp_data\Metadata\global-metadata.dat"
data = open(META, "rb").read()
fsize = len(data)
raw = [struct.unpack_from("<ii", data, 8 + i*8) for i in range(40)]

print("=== pair layout (index off size) ===")
for i, (o, s) in enumerate(raw):
    if s > 0 and 0 <= o < fsize:
        print(f"  pair{i:2d}: off {o:#10x} size {s:#10x}  end {o+s:#10x}")

def pair_of(off):
    for i, (o, s) in enumerate(raw):
        if s > 0 and o <= off < min(o+s, fsize):
            return i
    return -1

print("\n=== 'VecCtrl' occurrences (raw bytes) ===")
start = 0
hits = []
while True:
    i = data.find(b"VecCtrl", start)
    if i < 0:
        break
    hits.append(i)
    start = i + 1
print(f"count={len(hits)}")
for h in hits[:30]:
    # read the NUL/len-delimited string around
    end = data.find(b"\x00", h, h+200)
    s = data[h:end if end>0 else h+40]
    print(f"  @{h:#x} pair{pair_of(h)}: {s[:60]!r}")
