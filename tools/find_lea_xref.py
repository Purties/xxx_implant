# find_lea_xref.py - find lea instructions in dump referencing a given runtime VA
import sys
import struct

DUMP = r"d:\9-4#2\xxx\analysis\memscan\region_0_0x269C000.bin"
data = open(DUMP, "rb").read()
BASE = 0x80000000

target = int(sys.argv[1], 16)  # runtime VA (BASE + offset)
# scan for lea with rip-relative modrm: 48 8d / 4c 8d with modrm mod=00 rm=101
hits = []
i = 0
n = len(data) - 7
while i < n:
    b0 = data[i]
    if b0 in (0x48, 0x4C):
        b1 = data[i + 1]
        if b1 == 0x8D:
            modrm = data[i + 2]
            if (modrm & 0xC7) == 0x05:  # mod=00, rm=101 -> rip-relative
                disp = struct.unpack_from("<i", data, i + 3)[0]
                insn_end = BASE + i + 7
                if insn_end + disp == target:
                    hits.append(i)
    i += 1
print(f"lea xref to {target:#x}: {[hex(h) for h in hits]}")
