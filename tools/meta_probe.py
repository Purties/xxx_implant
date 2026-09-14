# meta_probe.py - probe global-metadata.dat header structure
import struct

META = r"C:\冒险岛online\mxdclassic\Maplestory_Classic_Data\il2cpp_data\Metadata\global-metadata.dat"
data = open(META, "rb").read()
print(f"size: {len(data):#x}")

magic, version = struct.unpack_from("<II", data, 0)
print(f"magic: {magic:#010x}  version: {version} ({version:#x})")

# Standard Il2CppGlobalMetadataHeader: magic(4) version(4) then N pairs of (offset:int32, size:int32)
# Print first 40 offset/size pairs as if standard layout
print("\n-- offset/size pairs (standard interpretation) --")
off = 8
for i in range(40):
    o, s = struct.unpack_from("<ii", data, 8 + i * 8)
    if o == 0 and s == 0:
        print(f"  [{i:2d}] hdr+{8+i*8:#x}: offset=0 size=0 (terminator?)")
        # don't break; show more
    else:
        sane = "OK" if 0 <= o < len(data) and 0 <= s < len(data) else "!!"
        print(f"  [{i:2d}] hdr+{8+i*8:#x}: offset={o:#x} size={s:#x} {sane}")
