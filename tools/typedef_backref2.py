# typedef_backref2.py - backref multiple sibling type names -> typedef record positions -> stride
import struct

META = r"C:\冒险岛online\mxdclassic\Maplestory_Classic_Data\il2cpp_data\Metadata\global-metadata.dat"
data = open(META, "rb").read()

P12_OFF, P12_SIZE = 0xa57e38, 0x12b040

names = ["VecCtrl", "VecCtrlDragon", "VecCtrlGrenade", "VecCtrlMob", "VecCtrlNpc",
         "VecCtrlPet", "VecCtrlSummoned", "VecCtrlUser", "VecCtrlUserPreview",
         "VecCtrlMob|MoveCtx", "VecCtrlNpc|MoveCtx", "VecCtrlPet|MoveCtx"]

# find exact NUL-terminated name in pair12 (avoid matching '.cs' variants or longer names)
def find_name(nm):
    needle = nm.encode() + b"\x00"
    res = []
    s = P12_OFF
    while True:
        i = data.find(needle, s, P12_OFF + P12_SIZE)
        if i < 0:
            break
        # ensure preceded by NUL or length-prefix boundary: accept all, tag pos
        res.append(i)
        s = i + 1
    return res

rows = []
for nm in names:
    poss = find_name(nm)
    for p in poss:
        reloff = p - P12_OFF
        # skip '.cs' prefixed strings: check byte before; if part of longer word skip? keep all
        needle = struct.pack("<I", reloff)
        s = 0
        while True:
            h = data.find(needle, s)
            if h < 0:
                break
            if not (P12_OFF <= h < P12_OFF + P12_SIZE) and not (0xc9e60 <= h < 0x597eb7):
                rows.append((nm, reloff, h))
            s = h + 1

rows.sort(key=lambda r: r[2])
print(f"{'name':28s} {'nameOff':>10s} {'hit@':>12s}  delta_from_prev")
prev = None
for nm, reloff, h in rows:
    d = f"{h - prev:#x}" if prev is not None else "-"
    print(f"{nm:28s} {reloff:#10x} {h:#12x}  {d}")
    prev = h

# dump 0x60 bytes around each hit to inspect record shape
print("\n=== record windows (hit assumed = nameIndex field) ===")
for nm, reloff, h in rows:
    lo = max(0, h - 8)
    vals = struct.unpack_from("<24I", data, lo)
    print(f"{nm} @{h:#x}:")
    print("   " + " ".join(f"{v:#x}" for v in vals))
