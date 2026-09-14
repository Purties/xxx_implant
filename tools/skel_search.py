# skel_search.py - generic wildcard skeleton search in new GA il2cpp section
# usage: skel_search.py "<hex bytes, ?? for wildcard>" [maxhits] [file=old|new]
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
    raise SystemExit("no il2cpp section")

def parse_pattern(pat):
    toks = pat.replace(",", " ").split()
    out = []
    for t in toks:
        if t in ("??", "?"):
            out.append(None)
        else:
            out.append(int(t, 16))
    return out

def main():
    pat = parse_pattern(sys.argv[1])
    maxhits = int(sys.argv[2]) if len(sys.argv) > 2 else 30
    which = sys.argv[3] if len(sys.argv) > 3 else "new"
    data, raw0, raw1, va0 = il2cpp_range(FILES[which])
    L = len(pat)
    # anchor on the first fixed byte for speed
    first_fixed = next(i for i, b in enumerate(pat) if b is not None)
    anchor = bytes([pat[first_fixed]])
    hits = []
    s = raw0
    while True:
        i = data.find(anchor, s, raw1 - L)
        if i < 0:
            break
        base = i - first_fixed
        if base >= raw0 and all(pat[k] is None or data[base + k] == pat[k] for k in range(L)):
            hits.append(va0 + (base - raw0))
            if len(hits) >= maxhits:
                break
        s = i + 1
    print(f"pattern len={L} hits={len(hits)}{' (truncated)' if len(hits)>=maxhits else ''}")
    for h in hits:
        print(f"  {h:#x}")

if __name__ == "__main__":
    main()
