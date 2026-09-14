# find_callers.py - find all direct `call rel32` sites targeting a given RVA inside il2cpp section
# usage: find_callers.py old|new <target_rva_hex>
import sys
import struct

FILES = {
    "old": r"d:\9-4#2\tools\GameAssembly_old_0902.dll",
    "new": r"C:\冒险岛online\mxdclassic\GameAssembly.dll",
}

def il2cpp_range(path):
    data = open(path, "rb").read()
    pe = struct.unpack_from("<I", data, 0x3C)[0]
    n = struct.unpack_from("<H", data, pe + 6)[0]
    osz = struct.unpack_from("<H", data, pe + 0x14)[0]
    so = pe + 0x18 + osz
    for i in range(n):
        s = so + i * 0x28
        name = data[s:s+8].rstrip(b"\x00").decode("ascii", "replace")
        vs, va, rs, rp = struct.unpack_from("<IIII", data, s + 8)
        if name == "il2cpp":
            return data, rp, rp + rs, va
    raise SystemExit("no il2cpp")

which = sys.argv[1]
target = int(sys.argv[2], 16)
data, raw0, raw1, va0 = il2cpp_range(FILES[which])

hits = []
s = raw0
while True:
    i = data.find(b"\xe8", s, raw1 - 5)
    if i < 0:
        break
    rel = struct.unpack_from("<i", data, i + 1)[0]
    site_va = va0 + (i - raw0)
    if site_va + 5 + rel == target:
        hits.append(site_va)
    s = i + 1
print(f"callers of {target:#x} in {which}: {len(hits)}")
for h in hits:
    print(f"  {h:#x}")
