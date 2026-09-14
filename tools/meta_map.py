# meta_map.py - empirical v39 metadata mapping
# pair3 = string table (method names hashed), pair10 = methodPointers?, pair12 = type-name table (len-prefixed)
import struct

META = r"C:\冒险岛online\mxdclassic\Maplestory_Classic_Data\il2cpp_data\Metadata\global-metadata.dat"
data = open(META, "rb").read()
pairs = []
for i in range(40):
    o, s = struct.unpack_from("<ii", data, 8 + i * 8)
    pairs.append((o, s))

GA_IL2CPP_LO, GA_IL2CPP_HI = 0x489000, 0x5384415   # GameAssembly il2cpp section VA range
GA_TEXT_LO, GA_TEXT_HI = 0x1000, 0x489000

# --- 1. pair[3] string table sample
o3, s3 = pairs[3]
print(f"=== pair3 (hdr 0x20) @{o3:#x} size {s3:#x} ===")
sample = data[o3:o3+0x200]
print("first 0x100 bytes:", sample[:0x100])
# count NULs in first 0x1000
print("NUL count first 0x1000:", data[o3:o3+0x1000].count(0))
for name in (b"Update\x00", b"Awake\x00", b"VecCtrlMob\x00", b"SetVelocity\x00", b"DoCombatStep\x00", b"SetDamaged\x00", b"SetImpactNext\x00"):
    idx = data.find(name, o3, o3 + s3)
    print(f"  find {name!r}: {hex(idx - o3) if idx >= 0 else 'NOT FOUND'}")

# --- 2. pair[10] methodPointers?
o10, s10 = pairs[10]
print(f"\n=== pair10 (hdr 0x58) @{o10:#x} size {s10:#x} ===")
qws = struct.unpack_from("<8Q", data, o10)
dws = struct.unpack_from("<16I", data, o10)
print("as qwords:", [hex(v) for v in qws])
print("as dwords:", [hex(v) for v in dws])
# stats over table
import collections
cnt_q = collections.Counter()
step = 8
inrange = 0
total = 0
for i in range(0, s10 - 8, 8):
    v = struct.unpack_from("<Q", data, o10 + i)[0]
    total += 1
    if GA_IL2CPP_LO <= v < GA_IL2CPP_HI or GA_TEXT_LO <= v < GA_TEXT_HI:
        inrange += 1
print(f"qword entries: {total}, in-GA-code-range: {inrange}")
inrange4 = 0
total4 = 0
for i in range(0, s10 - 4, 4):
    v = struct.unpack_from("<I", data, o10 + i)[0]
    total4 += 1
    if GA_IL2CPP_LO <= v < GA_IL2CPP_HI:
        inrange4 += 1
print(f"dword entries: {total4}, in-il2cpp-range: {inrange4}")

# --- 3. pair12 entries: length-prefixed parse
o12, s12 = pairs[12]
print(f"\n=== pair12 (hdr 0x68) @{o12:#x} size {s12:#x} len-prefixed parse ===")
entries = []
p = o12
end = o12 + s12
bad = 0
while p < end:
    ln = data[p]
    if ln == 0 or p + 1 + ln > end:
        bad += 1
        p += 1
        continue
    s = data[p+1:p+1+ln]
    entries.append((p - o12, s))
    p += 1 + ln
print(f"entries: {len(entries)}, bad-skip bytes: {bad}, end residue: {end - p:#x}")
# find our classes
KEYS = [b"|VecCtrlMob", b"|VecCtrlUser", b"|VecCtrl", b"|Mob", b"|UserLocal", b"|MobPool", b"VecCtrlMob|"]
for k in KEYS:
    hits = [(off, s) for off, s in entries if k in s]
    print(f"  {k!r}: {len(hits)}")
    for off, s in hits[:6]:
        print(f"     entryOff={off:#x} idx~? {s[:70]!r}")
# index of exact VecCtrlMob type
for i, (off, s) in enumerate(entries):
    if s == b"Msc.Game.Object.Control|VecCtrlMob":
        print(f"  EXACT VecCtrlMob at entry index {i}, off {off:#x}")
    if s == b"Msc.Game.Object.Control|VecCtrlUser":
        print(f"  EXACT VecCtrlUser at entry index {i}, off {off:#x}")
