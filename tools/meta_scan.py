# meta_scan.py - locate key tables in v39 metadata
import struct, re, hashlib

META = r"C:\冒险岛online\mxdclassic\Maplestory_Classic_Data\il2cpp_data\Metadata\global-metadata.dat"
data = open(META, "rb").read()

# pairs from header probe
pairs = []
for i in range(40):
    o, s = struct.unpack_from("<ii", data, 8 + i * 8)
    pairs.append((8 + i * 8, o, s))

print("== 1. verify slot 0x58 (pair10) as methodPointers ==")
o, s = pairs[10][1], pairs[10][2]
vals = struct.unpack_from("<16Q", data, o)
for v in vals:
    insec = 0x489000 <= v < 0x5378000
    print(f"  {v:#x}  {'il2cpp-code' if insec else ''}")
print(f"  count = {s} / 8 = {s//8}")

print("\n== 2. scan for 64-hex-char string density (hashed method names) ==")
hexpat = re.compile(rb"[0-9a-f]{64}")
counts = {}
for m in hexpat.finditer(data):
    bucket = m.start() // 0x10000
    counts[bucket] = counts.get(bucket, 0) + 1
top = sorted(counts.items(), key=lambda kv: -kv[1])[:10]
for bucket, cnt in top:
    print(f"  region {bucket*0x10000:#x}..{(bucket+1)*0x10000:#x}: {cnt} hash-strings")

print("\n== 3. scan for 'namespace|type' plain strings ==")
pipepat = re.compile(rb"[A-Za-z_][A-Za-z0-9_.<>]{1,40}\|[A-Za-z_][A-Za-z0-9_.<>]{1,40}")
counts2 = {}
samples = {}
for m in pipepat.finditer(data):
    bucket = m.start() // 0x10000
    counts2[bucket] = counts2.get(bucket, 0) + 1
    samples.setdefault(bucket, []).append(m.group().decode())
top2 = sorted(counts2.items(), key=lambda kv: -kv[1])[:10]
for bucket, cnt in top2:
    print(f"  region {bucket*0x10000:#x}..{(bucket+1)*0x10000:#x}: {cnt}  e.g. {samples[bucket][:3]}")

print("\n== 4. SHA-256 collision test on known method names ==")
names = ["SetVelocity", "SetImpactNext", "DoCombatStep", "SetDamaged", "Update",
         "setVelocity", "setImpactNext", "Awake", "Start", "FixedUpdate"]
# candidate string regions: top hex buckets
cand_regions = sorted({b * 0x10000 for b, _ in counts.items() if _ > 100})
print(f"  candidate hash regions: {[hex(r) for r in cand_regions[:6]]}")
hexset = set()
for m in hexpat.finditer(data):
    hexset.add(m.group().decode())
print(f"  total unique 64-hex strings: {len(hexset)}")
for n in names:
    h = hashlib.sha256(n.encode()).hexdigest()
    hit = h in hexset
    print(f"  sha256({n!r}) = {h[:16]}... {'*** HIT ***' if hit else 'miss'}")
