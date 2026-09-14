# token_scan.py - locate methods table via token arithmetic progression
# Il2CppMethodDefinition.token = 0x06000001 + i, strictly +1 per record
# also typedef table: token = 0x02000001 + i
import struct

META = r"C:\冒险岛online\mxdclassic\Maplestory_Classic_Data\il2cpp_data\Metadata\global-metadata.dat"
data = open(META, "rb").read()
fsize = len(data)
raw = [struct.unpack_from("<ii", data, 8 + i*8) for i in range(40)]
pairs = []
for o, s in raw:
    if o < 0 or s <= 0 or o >= fsize:
        pairs.append((0, 0))
    else:
        pairs.append((o, min(s, fsize - o)))

def scan_tokens(prefix, min_run=64):
    """find longest run where dword value == prefix|k, k increasing by 1 every `step` dwords"""
    best = None
    for pi, (o, s) in enumerate(pairs):
        if s < 0x100:
            continue
        n4 = s // 4
        vals = struct.unpack_from(f"<{n4}I", data, o)
        # candidate start positions: value == prefix|1 .. prefix|0x1000
        # then extend: value[j+step] == value[j]+1
        for st in range(n4):
            v0 = vals[st]
            if (v0 & 0xFF000000) != prefix:
                continue
            k0 = v0 & 0x00FFFFFF
            if k0 < 1 or k0 > 0x40000:
                continue
            # try stride in dwords 4..16
            for step in range(4, 17):
                j = st + step
                cnt = 1
                while j < n4 and vals[j] == v0 + cnt:
                    cnt += 1
                    j += step
                if cnt >= min_run:
                    rec = (cnt, pi, st, step, v0)
                    if best is None or cnt > best[0]:
                        best = rec
                    # also extend backwards to find true start
    return best

for prefix, label in ((0x06000000, "methods"), (0x02000000, "typedefs")):
    b = scan_tokens(prefix)
    if b:
        cnt, pi, st, step, v0 = b
        o, s = pairs[pi]
        print(f"{label}: pair{pi} start_dword={st} (file {o+st*4:#x}) step={step} dwords ({step*4:#x} bytes) run={cnt} first_token={v0:#x}")
    else:
        print(f"{label}: no run found")

# refine: for the best methods hit, extend backwards & forwards fully
def full_run(prefix):
    out = []
    for pi, (o, s) in enumerate(pairs):
        if s < 0x100:
            continue
        n4 = s // 4
        vals = struct.unpack_from(f"<{n4}I", data, o)
        st = 0
        while st < n4:
            v0 = vals[st]
            if (v0 & 0xFF000000) != prefix or not (1 <= (v0 & 0xFFFFFF) <= 0x40000):
                st += 1
                continue
            for step in range(4, 17):
                # backward
                b = st
                while b - step >= 0 and vals[b-step] == vals[b] - 1:
                    b -= step
                f = st
                while f + step < n4 and vals[f+step] == vals[f] + 1:
                    f += step
                cnt = (f - b)//step + 1
                if cnt >= 1000:
                    out.append((cnt, pi, b, f, step, vals[b]))
            st += 1
    out.sort(reverse=True)
    return out

print("\n=== full runs >= 1000 ===")
for cnt, pi, b, f, step, tok in full_run(0x06000000)[:5]:
    o, s = pairs[pi]
    print(f"methods: pair{pi} file [{o+b*4:#x}..{o+f*4:#x}] step={step*4:#x} count={cnt} tok0={tok:#x}")
for cnt, pi, b, f, step, tok in full_run(0x02000000)[:5]:
    o, s = pairs[pi]
    print(f"typedefs: pair{pi} file [{o+b*4:#x}..{o+f*4:#x}] step={step*4:#x} count={cnt} tok0={tok:#x}")
