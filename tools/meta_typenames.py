# meta_typenames.py - enumerate type names from pair12, grep candidates
import struct

META = r"C:\冒险岛online\mxdclassic\Maplestory_Classic_Data\il2cpp_data\Metadata\global-metadata.dat"
data = open(META, "rb").read()

pairs = []
for i in range(40):
    o, s = struct.unpack_from("<ii", data, 8 + i * 8)
    pairs.append((o, s))

o12, s12 = pairs[12]
region = data[o12:o12+s12]
names = region.split(b"\x00")
names = [n.decode("utf-8", "replace") for n in names if n]
print(f"pair12 {o12:#x} size {s12:#x}, strings: {len(names)}")

# candidate classes related to movement/mob/vecctrl/combat
KEYS = ["vec", "mob", "move", "combat", "damage", "impact", "velocity", "ctrl",
        "monster", "physic", "walk", "character", "user", "avatar"]
hits = {}
for n in names:
    ln = n.lower()
    for k in KEYS:
        if k in ln:
            hits.setdefault(k, []).append(n)
            break
for k in KEYS:
    lst = hits.get(k, [])
    print(f"\n-- {k} ({len(lst)}) --")
    for n in lst[:40]:
        print("   ", n)
