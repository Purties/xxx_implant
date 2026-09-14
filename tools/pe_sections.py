# pe_sections.py - parse dumped PE header & section layout
import struct

BIN = r"d:\9-4#2\xxx\analysis\memscan\region_0_0x269C000.bin"
data = open(BIN, "rb").read()

print(f"magic: {data[:2]}")
e_lfanew = struct.unpack_from("<I", data, 0x3C)[0]
print(f"e_lfanew={e_lfanew:#x}  sig={data[e_lfanew:e_lfanew+4]}")
coff = e_lfanew + 4
machine, nsec, ts, _, _, optsize, chars = struct.unpack_from("<HHIIIHH", data, coff)
print(f"machine={machine:#x} sections={nsec} timestamp={ts:#x} optsize={optsize:#x} chars={chars:#x}")
opt = coff + 20
magic = struct.unpack_from("<H", data, opt)[0]
imgbase = struct.unpack_from("<Q", data, opt + 24)[0]
ep = struct.unpack_from("<I", data, opt + 16)[0]
print(f"optmagic={magic:#x} imagebase={imgbase:#x} entrypoint={ep:#x}")
# data dirs
ddir = opt + 112
names = ["export","import","resource","exception","cert","reloc","debug","arch","globalptr","tls","loadcfg","boundiat","iat","delay","clr","resv"]
for i, nm in enumerate(names):
    va, sz = struct.unpack_from("<II", data, ddir + i*8)
    if va:
        print(f"  dir[{i:2}] {nm:10} va={va:#x} size={sz:#x}")
sec = opt + optsize
for i in range(nsec):
    o = sec + i*40
    nm = data[o:o+8].rstrip(b"\x00").decode("ascii", "replace")
    vs, va, rs, rp = struct.unpack_from("<IIII", data, o+8)
    ch = struct.unpack_from("<I", data, o+36)[0]
    print(f"  sec[{i}] {nm:8} va={va:#10x} vs={vs:#10x} raw={rp:#10x} rs={rs:#10x} chars={ch:#x}")
