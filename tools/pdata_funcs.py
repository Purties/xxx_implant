# pdata_funcs.py - parse .pdata RUNTIME_FUNCTION entries; query functions around given RVAs
# usage: pdata_funcs.py old|new <rva_hex> [rva_hex2 ...]
import sys
import struct

FILES = {
    "old": r"d:\9-4#2\tools\GameAssembly_old_0902.dll",
    "new": r"C:\冒险岛online\mxdclassic\GameAssembly.dll",
}

def parse(path):
    data = open(path, "rb").read()
    pe = struct.unpack_from("<I", data, 0x3C)[0]
    n = struct.unpack_from("<H", data, pe + 6)[0]
    osz = struct.unpack_from("<H", data, pe + 0x14)[0]
    so = pe + 0x18 + osz
    secs = {}
    for i in range(n):
        s = so + i * 0x28
        name = data[s:s+8].rstrip(b"\x00").decode("ascii", "replace")
        vs, va, rs, rp = struct.unpack_from("<IIII", data, s + 8)
        secs[name] = (va, vs, rp, rs)
    va, vs, rp, rs = secs[".pdata"]
    entries = []
    for off in range(rp, rp + rs, 12):
        b, e, u = struct.unpack_from("<III", data, off)
        entries.append((b, e, u))
    entries.sort()
    return entries

def main():
    which = sys.argv[1]
    entries = parse(FILES[which])
    print(f"{which}: {len(entries)} pdata entries")
    for a in sys.argv[2:]:
        rva = int(a, 16)
        # find index of entry with begin <= rva
        import bisect
        begins = [e[0] for e in entries]
        i = bisect.bisect_right(begins, rva) - 1
        for j in range(max(0, i - 1), min(len(entries), i + 3)):
            b, e, u = entries[j]
            mark = " <<<" if b == rva else (" (contains)" if b <= rva < e else "")
            print(f"  [{j}] begin={b:#x} end={e:#x} len={e-b:#x}{mark}")

if __name__ == "__main__":
    main()
