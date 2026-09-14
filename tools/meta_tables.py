# meta_tables.py - empirically locate v39 tables: methodPointers run, methods table (0x06xxxxxx tokens),
# typedef table (methodStart monotonic), + sha256 name-collision test
import struct, hashlib, re

META = r"C:\冒险岛online\mxdclassic\Maplestory_Classic_Data\il2cpp_data\Metadata\global-metadata.dat"
data = open(META, "rb").read()
pairs = []
for i in range(40):
    o, s = struct.unpack_from("<ii", data, 8 + i * 8)
    pairs.append((o, s))

GA_LO, GA_HI = 0x489000, 0x5384415

# --- A. pair10: longest run of dwords in GA il2cpp range
print("=== A. pair10 dword-run analysis ===")
o, s = pairs[10]
best = (0, 0)  # len, start_off
cur_len = 0
cur_start = 0
n4 = s // 4
vals = struct.unpack_from(f"<{n4}I", data, o)
runs = []
for i, v in enumerate(vals):
    if GA_LO <= v < GA_HI:
        if cur_len == 0:
            cur_start = i
        cur_len += 1
    else:
        if cur_len >= 64:
            runs.append((cur_len, cur_start))
        cur_len = 0
if cur_len >= 64:
    runs.append((cur_len, cur_start))
runs.sort(reverse=True)
print(f"runs>=64: {len(runs)}, top5: {[(l, hex(st*4)) for l, st in runs[:5]]}")
if runs:
    l, st = runs[0]
    print(f"longest run: {l} entries at pair10+{st*4:#x} (file {o + st*4:#x})")
    print(" first vals:", [hex(x) for x in vals[st:st+8]])

# --- B. methods table: scan big pairs for 0x06xxxxxx ascending token field
print("\n=== B. methods-table token scan ===")
cand_pairs = [i for i, (po, ps) in enumerate(pairs) if ps > 0x100000]
for pi in cand_pairs:
    po, ps = pairs[pi]
    for stride in (0x20, 0x24, 0x28, 0x2c, 0x30, 0x34, 0x38, 0x3c, 0x40):
        nrec = ps // stride
        if nrec < 10000:
            continue
        for f in range(0, stride - 4, 4):
            hits = 0
            prev = 0
            mono = 0
            for r in range(0, min(nrec, 4000)):
                v = struct.unpack_from("<I", data, po + r * stride + f)[0]
                if 0x06000001 <= v <= 0x06080000:
                    hits += 1
                    if v >= prev:
                        mono += 1
                    prev = v
                else:
                    break  # require contiguous from record 0
            if hits > 2000 and mono > hits * 0.95:
                print(f"  pair{pi} stride={stride:#x} field+{f:#x}: {hits} method-token records (mono {mono})")

# --- D. sha256 collision test
print("\n=== D. sha256 name collisions in pair3 ===")
o3, s3 = pairs[3]
region = data[o3:o3+s3]
names = ["VecCtrlMob", "VecCtrlUser", "SetVelocity", "SetImpactNext", "DoCombatStep", "SetDamaged",
         "Msc.Game.Object.Control.VecCtrlMob", "Msc.Game.Object.Control|VecCtrlMob",
         "Msc.Game.Object.Control.VecCtrlMob.SetVelocity", "VecCtrlMob.SetVelocity",
         "Msc.Game.Object.Control|VecCtrlUser", "Msc.Game.Object.Control.VecCtrlUser",
         "Msc.Game.Object|UserLocal", "Update"]
for nm in names:
    h = hashlib.sha256(nm.encode()).hexdigest().encode()
    idx = region.find(h)
    if idx >= 0:
        print(f"  HIT sha256({nm!r}) at pair3+{idx:#x}")
    else:
        print(f"  miss {nm!r}")
