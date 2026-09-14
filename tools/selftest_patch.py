# selftest_patch.py - verify RvaPatcher constants against the dump (offline sanity)
import re
import struct

cs = open(r"d:\9-4#2\tools\RvaPatcher.cs", encoding="utf-8").read()
dump = open(r"d:\9-4#2\xxx\analysis\memscan\region_0_0x269C000.bin", "rb").read()

# 1) signature
m = re.search(r'GetBytes\("([0-9a-f]+)"\)', cs)
sig = m.group(1)
ref = bytes(dump[0x183FC0:0x183FC0 + len(sig)]).decode()
print(f"1) signature len={len(sig)} dump_match={sig == ref}")

# 2) sites
sites = re.findall(r'new Site\("(\w+)",\s*0x([0-9A-Fa-f]+),\s*0x([0-9A-Fa-f]+),\s*0x([0-9A-Fa-f]+),\s*0x([0-9A-Fa-f]+)\)', cs)
print(f"2) sites parsed from C#: {len(sites)}")
ok_all = True
for name, off, old, new, slot in sites:
    off = int(off, 16); old = int(old, 16); new = int(new, 16); slot = int(slot, 16)
    b = dump[off:off + 7]
    disp = struct.unpack_from("<i", dump, off + 3)[0]
    site_ok = (b[0] == 0x48 and b[1] == 0x8D and b[2] == 0x83 and disp == old)
    # slot region is beyond dump (0xBE1xxx > 0x87F000), just report
    in_dump = "in-dump" if slot < len(dump) else "beyond-dump"
    print(f"   {name:14s} lea@{off:#x} bytes={b.hex(' ')} disp={disp:#x} old_ok={site_ok} new={new:#x} slot@{slot:#x}({in_dump})")
    ok_all = ok_all and site_ok
print(f"3) all lea sites OK: {ok_all}")
