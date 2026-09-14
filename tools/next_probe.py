# next_probe.py - 1) GA preferred base + whole-file pointer runs  2) pair15 record inspection
import struct, pefile, collections

GA = r"C:\冒险岛online\mxdclassic\GameAssembly.dll"
META = r"C:\冒险岛online\mxdclassic\Maplestory_Classic_Data\il2cpp_data\Metadata\global-metadata.dat"

pe = pefile.PE(GA, fast_load=True)
print(f"GA preferred ImageBase: {pe.OPTIONAL_HEADER.ImageBase:#x}")
BASE = pe.OPTIONAL_HEADER.ImageBase
ga = open(GA, "rb").read()
lo, hi = BASE + 0x489000, BASE + 0x5388000

print("\n=== whole-file qword runs (aligned 8, in code range) ===")
runs = []
run_len = 0
run_start = 0
CH = 1 << 22
pos = 0
n = len(ga)
while pos < n:
    chunk = ga[pos:pos+CH]
    n8 = len(chunk) // 8
    vals = struct.unpack_from(f"<{n8}Q", chunk, 0)
    for i, v in enumerate(vals):
        if lo <= v < hi:
            if run_len == 0:
                run_start = pos + i*8
            run_len += 1
        else:
            if run_len >= 256:
                runs.append((run_len, run_start))
            run_len = 0
    pos += len(chunk)
runs.sort(reverse=True)
for l, st in runs[:6]:
    print(f"  len={l} raw={st:#x}")
if runs:
    l, st = runs[0]
    vals = struct.unpack_from("<8Q", ga, st)
    for i, v in enumerate(vals):
        print(f"    [{i}] {v:#x} rva={v-BASE:#x}")

print("\n=== pair15 record inspection ===")
data = open(META, "rb").read()
pairs = [struct.unpack_from("<ii", data, 8 + i*8) for i in range(40)]
o15, s15 = pairs[15]
o3, s3 = pairs[3]
def nm(idx):
    if not (0 <= idx < s3):
        return None
    e = data.find(b"\x00", o3+idx, o3+s3)
    if e < 0:
        return None
    return data[o3+idx:e][:60]
for r in range(6):
    base = o15 + r*0x28
    dws = struct.unpack_from("<10I", data, base)
    print(f"  rec{r}: " + " ".join(f"{v:#x}" for v in dws))
    print(f"        name[0]={nm(dws[0])!r} name[1]={nm(dws[1])!r}")

# field monotonicity: for each dword field, check monotonic non-decreasing across all 38303 records
nrec = s15 // 0x28
print(f"\npair15 nrec={nrec}")
for f in range(0, 0x28, 4):
    mono = True
    prev = -1
    for r in range(nrec):
        v = struct.unpack_from("<I", data, o15 + r*0x28 + f)[0]
        if v < prev:
            mono = False
            break
        prev = v
    # range
    vals0 = struct.unpack_from("<I", data, o15 + f)[0]
    valsE = struct.unpack_from("<I", data, o15 + (nrec-1)*0x28 + f)[0]
    print(f"  field+{f:#x}: monotonic={mono} first={vals0:#x} last={valsE:#x}")
