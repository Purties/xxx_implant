# meta_hash_hunt.py - find sha256 raw digests of known names inside metadata
import hashlib

META = r"C:\冒险岛online\mxdclassic\Maplestory_Classic_Data\il2cpp_data\Metadata\global-metadata.dat"
data = open(META, "rb").read()

names = ["SetVelocity", "SetImpactNext", "DoCombatStep", "SetDamaged", "Update",
         "setVelocity", "setImpactNext", "doCombatStep", "setDamaged", "update",
         "Awake", "Start", "FixedUpdate", "OnEnable", "get_position", "Next"]

def variants(n):
    yield "raw", n.encode()
    yield "utf16le", n.encode("utf-16-le")
    yield "lower", n.lower().encode()
    yield "nullterm", n.encode() + b"\x00"

found = []
for n in names:
    for tag, b in variants(n):
        d = hashlib.sha256(b).digest()
        idx = data.find(d)
        if idx >= 0:
            found.append((n, tag, idx))
            print(f"*** HIT sha256({n!r},{tag}) @ {idx:#x}")
print(f"total hits: {len(found)}")
