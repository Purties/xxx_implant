# probe_blobs.py - 1) test if 5 blobs match new GameAssembly (find new RVAs)
#                  2) follow row-struct pointers at 0x185780 rows
#                  3) hexdump around 0x6d050 (Update rva refs)
import struct

BIN = r"d:\9-4#2\xxx\analysis\memscan\region_0_0x269C000.bin"
GA  = r"C:\冒险岛online\mxdclassic\GameAssembly.dll"
data = open(BIN, "rb").read()
ga = open(GA, "rb").read()
print(f"dump={len(data):#x}  gameassembly={len(ga):#x}")

# GameAssembly section map (from crash_point_bytes.txt): VA -> RawPtr
sections = [
    (0x1000,    0x487f38,   0x400),      # .text
    (0x489000,  0x4efb415,  0x488400),   # il2cpp
    (0x5385000, 0x156c1e2,  0x5383a00),  # .rdata
    (0x68f2000, 0x9a4e20,   0x68efc00),  # .data
    (0x7297000, 0x307434,   0x6cb5600),  # .pdata
]
def va_to_raw(va):
    for v, s, r in sections:
        if v <= va < v + s:
            return r + (va - v)
    return None

blobs = [0x714350, 0x7156e0, 0x716900, 0x717e20, 0x719180]
hashes = ["f381d853", "cdeaa78e", "a6636c74", "e1f1fe26", "fa00269a"]

print("\n=== blob -> new GameAssembly match test (multi-window) ===")
for bi, b in enumerate(blobs):
    found_any = False
    for off_in_blob in range(0, 0x400, 0x40):
        for wlen in (32, 48):
            needle = data[b+off_in_blob:b+off_in_blob+wlen]
            idx = ga.find(needle)
            if idx >= 0:
                # map raw file offset to VA
                va = None
                for v, s, r in sections:
                    if r <= idx < r + s:
                        va = v + (idx - r)
                print(f"blob{bi} ({hashes[bi]}..) +{off_in_blob:#x} len{wlen}: GA raw {idx:#x} va {hex(va) if va else '?'}")
                found_any = True
    if not found_any:
        print(f"blob{bi} ({hashes[bi]}..): NO match in current GameAssembly")

print("\n=== row struct pointer targets ===")
rows_base = 0x185780
for r in range(5):
    ro = rows_base + r*0x40
    vals = struct.unpack_from("<16I", data, ro)
    print(f"-- row{r}: " + " ".join(f"{v:#x}" for v in vals))
    for v in vals:
        if 0x10000 < v < len(data):
            chunk = data[v:v+64]
            asc = "".join(chr(c) if 32 <= c < 127 else "." for c in chunk)
            print(f"   deref {v:#x}: {chunk[:32].hex(' ')}  |{asc[:48]}|")

print("\n=== @0x6d000..0x6d220 (Update rva=0x1660650 refs area) ===")
for i in range(0x6d000, 0x6d220, 16):
    chunk = data[i:i+16]
    print(f"@{i:#x}  " + " ".join(f"{b:02x}" for b in chunk) + "  " + "".join(chr(b) if 32<=b<127 else "." for b in chunk))
