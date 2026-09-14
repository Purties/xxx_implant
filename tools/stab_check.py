# stab_check.py - how stable is il2cpp code between old/new? sample 16B chunks verbatim hit rate
import struct

OLD = r"d:\9-4#2\tools\GameAssembly_old_0902.dll"
NEW = r"C:\冒险岛online\mxdclassic\GameAssembly.dll"
old = open(OLD, "rb").read()
new = open(NEW, "rb").read()

# old il2cpp: VA 0x487000 raw 0x485800 size 0x4e3c600 ; new il2cpp: VA 0x489000 raw 0x488400 size 0x4efb600
OLD_RAW, OLD_SZ = 0x485800, 0x4e3c600
NEW_RAW, NEW_SZ = 0x488400, 0x4efb600
newcode = new[NEW_RAW:NEW_RAW+NEW_SZ]

import random
random.seed(1)
N = 4000
hits16 = 0
hits12 = 0
hits8 = 0
for _ in range(N):
    off = OLD_RAW + random.randrange(0, OLD_SZ - 64)
    c16 = old[off:off+16]
    c12 = old[off:off+12]
    c8 = old[off:off+8]
    if newcode.find(c16) >= 0:
        hits16 += 1
    if newcode.find(c12) >= 0:
        hits12 += 1
    if newcode.find(c8) >= 0:
        hits8 += 1
print(f"verbatim chunk hit rate in new il2cpp: 8B {hits8/N:.1%}  12B {hits12/N:.1%}  16B {hits16/N:.1%}")

# also .text stability
OLD_T_RAW, OLD_T_SZ = 0x400, 0x485400
NEW_T_RAW, NEW_T_SZ = 0x400, 0x488000
newt = new[NEW_T_RAW:NEW_T_RAW+NEW_T_SZ]
h = 0
for _ in range(2000):
    off = OLD_T_RAW + random.randrange(0, OLD_T_SZ - 64)
    if newt.find(old[off:off+16]) >= 0:
        h += 1
print(f".text 16B hit rate: {h/2000:.1%}")
