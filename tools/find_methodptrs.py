# find_methodptrs.py - locate methodPointers qword array in GameAssembly + methods table structure in metadata
import struct

GA = r"C:\冒险岛online\mxdclassic\GameAssembly.dll"
META = r"C:\冒险岛online\mxdclassic\Maplestory_Classic_Data\il2cpp_data\Metadata\global-metadata.dat"

ga = open(GA, "rb").read()
print(f"GA size {len(ga):#x}")

# il2cpp section: VA 0x489000 raw 0x488400 size 0x4efb600
SEC_VA, SEC_RAW, SEC_SIZE = 0x489000, 0x488400, 0x4efb600
BASE = 0x180000000  # assumed preferred base
lo, hi = BASE + 0x489000, BASE + 0x5388000

# scan qwords at 8-aligned positions in il2cpp section; find longest run of in-range values
raw_end = SEC_RAW + SEC_SIZE
best = []
cur_start = None
cur_len = 0
off = SEC_RAW
# speed: iterate with struct.unpack in chunks
CH = 1 << 20
pos = SEC_RAW
abspos = SEC_RAW
run_start = 0
run_len = 0
runs = []
while pos < raw_end:
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
if run_len >= 256:
    runs.append((run_len, run_start))
runs.sort(reverse=True)
print("=== qword runs (in GA code VA range, base 0x180000000) ===")
for l, st in runs[:8]:
    va = SEC_VA + (st - SEC_RAW)
    print(f"  len={l} raw={st:#x} va={va:#x}")
if runs:
    l, st = runs[0]
    vals = struct.unpack_from("<16Q", ga, st)
    print("  first 16 qwords of longest run:")
    for i, v in enumerate(vals):
        print(f"    [{i}] {v:#x}  (rva {v-BASE:#x})")

# --- metadata: methods table structure detection
data = open(META, "rb").read()
pairs = [struct.unpack_from("<ii", data, 8 + i*8) for i in range(40)]
o3, s3 = pairs[3]

def valid_nameidx(v):
    if not (0 <= v < s3 - 1):
        return False
    b = data[o3 + v]
    return b != 0

print("\n=== methods table candidates (nameIndex@f0 into pair3, u16 small fields) ===")
for pi, (po, ps) in enumerate(pairs):
    if ps < 0x100000:
        continue
    for stride in (0x20, 0x24, 0x28, 0x2c, 0x30, 0x34, 0x38, 0x40):
        nrec = ps // stride
        if not (30000 <= nrec <= 600000):
            continue
        ok = 0
        test = min(nrec, 3000)
        for r in range(test):
            base = po + r * stride
            nameidx = struct.unpack_from("<I", data, base)[0]
            if valid_nameidx(nameidx):
                ok += 1
        if ok > test * 0.98:
            print(f"  pair{pi} stride={stride:#x} nrec={nrec}: nameidx-valid {ok}/{test}")
