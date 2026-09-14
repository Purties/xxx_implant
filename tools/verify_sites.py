# verify_sites.py - verify the 5 dispatch lea sites in the dump and emit patch table
import struct

DUMP = r"d:\9-4#2\xxx\analysis\memscan\region_0_0x269C000.bin"
data = open(DUMP, "rb").read()

SITES = [
    ("SetImpactNext", 0x127cdb, 0x11be670, 0x1214940),
    ("SetVelocity",   0x127d07, 0x11be640, 0x12144f0),
    ("DoCombatStep",  0x127d33, 0x11bef10, 0x1215270),
    ("InputUpdate",   0x127dd5, 0x1660650, 0x14db0b0),
    ("SetDamaged",    0x12800a, 0x1049b70, 0x10d74b0),
]
print(f"{'hook':14s} {'site_off':>10s} {'bytes':22s} {'old_disp':>10s} {'new_disp':>10s} ok")
for name, off, old, new in SITES:
    b = data[off:off+7]
    disp = struct.unpack_from("<i", data, off + 3)[0]
    ok = (b[0] == 0x48 and b[1] == 0x8D and b[2] == 0x83 and disp == old)
    print(f"{name:14s} {off:#010x} {b.hex(' '):22s} {disp:#010x} {new:#010x} {'OK' if ok else 'MISMATCH!'}")
