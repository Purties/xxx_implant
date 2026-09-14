# dump_disasm.py - disasm a region of the injected DLL dump
import sys
from capstone import Cs, CS_ARCH_X86, CS_MODE_64

data = open(r"d:\9-4#2\xxx\analysis\memscan\region_0_0x269C000.bin", "rb").read()
BASE = 0x80000000
md = Cs(CS_ARCH_X86, CS_MODE_64)

off = int(sys.argv[1], 16)
count = int(sys.argv[2]) if len(sys.argv) > 2 else 12
n = 0
for ins in md.disasm(data[off:off + count * 10], BASE + off):
    print(f"  @{off + (ins.address - (BASE + off)):#x} {ins.mnemonic:8s} {ins.op_str}")
    n += 1
    if n >= count:
        break
