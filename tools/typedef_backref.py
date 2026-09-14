# typedef_backref.py - backreference 'VecCtrlMob' name offset (pair12-relative) to find typedef table
import struct, collections

META = r"C:\冒险岛online\mxdclassic\Maplestory_Classic_Data\il2cpp_data\Metadata\global-metadata.dat"
data = open(META, "rb").read()
fsize = len(data)

P12_OFF, P12_SIZE = 0xa57e38, 0x12b040
name_off = 0xa70fe9 - P12_OFF   # 0x191b1
print(f"'VecCtrlMob' pair12-relative offset: {name_off:#x}")

needle = struct.pack("<I", name_off)
hits = []
s = 0
while True:
    i = data.find(needle, s)
    if i < 0:
        break
    hits.append(i)
    s = i + 1
print(f"dword hits for {name_off:#x}: {len(hits)}")

# exclude hits inside the string heaps themselves
def in_heap(i):
    return (P12_OFF <= i < P12_OFF + P12_SIZE) or (0xc9e60 <= i < 0x597eb7)

ext = [h for h in hits if not in_heap(h)]
print(f"outside string heaps: {len(ext)}")
for h in ext[:40]:
    ctx = struct.unpack_from("<8I", data, h - 16)
    print(f"  @{h:#x}: [-16..] " + " ".join(f"{v:#x}" for v in ctx))

# If many hits cluster in one region with regular stride, that region is the typedef table.
# Histogram of hit alignment mod candidate strides:
for stride in (0x24, 0x28, 0x2c, 0x30, 0x34, 0x38, 0x3c, 0x40, 0x44, 0x48, 0x4c, 0x50, 0x54, 0x58, 0x5c, 0x60, 0x64, 0x68, 0x6c, 0x70, 0x74, 0x78, 0x7c, 0x80, 0x84, 0x88, 0x8c, 0x90):
    pass  # stride determined after we see hit distribution
print("\nhit deltas:", [hex(ext[i+1]-ext[i]) for i in range(min(len(ext)-1, 20))])
