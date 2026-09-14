# classify_unresolved.py - 对 dispatch_identity.tsv 中 NOT_METHOD_ENTRY 的 79 个 RVA 定性
# 方法：.pdata 函数边界 + 指令字节特征（thunk jmp / 函数体中部 / 数据区）
import pefile, sys

GA = r"c:\workspace\9-4#2\tools\GameAssembly_old_0902.dll"
TSV = r"c:\workspace\9-4#2\xxx\analysis\dispatch_identity.tsv"

pe = pefile.PE(GA, fast_load=True)
pe.parse_data_directories(directories=[
    pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_EXCEPTION"],
])
funcs = sorted((e.struct.BeginAddress, e.struct.EndAddress) for e in pe.DIRECTORY_ENTRY_EXCEPTION)
print(f".pdata functions: {len(funcs)}")

import bisect
begins = [f[0] for f in funcs]
def func_of(rva):
    i = bisect.bisect_right(begins, rva) - 1
    if i >= 0 and funcs[i][0] <= rva < funcs[i][1]:
        return funcs[i]
    return None

def read_at(rva, n=16):
    for s in pe.sections:
        if s.VirtualAddress <= rva < s.VirtualAddress + s.Misc_VirtualSize:
            off = s.PointerToRawData + (rva - s.VirtualAddress)
            return pe.__data__[off:off+n]
    return b""

rows = [l.rstrip("\n").split("\t") for l in open(TSV, encoding="utf-8")][1:]
un = [(int(r[0],16), r[1]) for r in rows if r[1] == "NOT_METHOD_ENTRY"]
print(f"unresolved: {len(un)}")

import collections
cat = collections.Counter()
out = open(r"c:\workspace\9-4#2\xxx\analysis\dispatch_unresolved.tsv", "w", encoding="utf-8")
out.write("rva\tcategory\tdetail\n")
for rva in sorted(r for r, _ in un):
    f = func_of(rva)
    b = read_at(rva, 8)
    if f:
        off = rva - f[0]
        # 函数首字节特征
        if b[:2] == b"\xff\x25":
            c, d = "JMP_THUNK", f"jmp[rip] @in_func {f[0]:#x}+{off:#x}"
        elif b[:1] == b"\xe9":
            c, d = "JMP_REL", f"jmp rel32 @in_func {f[0]:#x}+{off:#x}"
        elif off == 0:
            c, d = "FUNC_HEAD_NOT_IN_DUMP", f"func {f[0]:#x} size {f[1]-f[0]:#x}"
        else:
            c, d = "MID_FUNCTION", f"in {f[0]:#x}..{f[1]:#x} +{off:#x} bytes={b.hex()}"
    else:
        if b[:2] == b"\xff\x25": c, d = "JMP_THUNK", f"standalone bytes={b.hex()}"
        elif b[:1] == b"\xe9":   c, d = "JMP_REL", f"standalone bytes={b.hex()}"
        else:                    c, d = "DATA_OR_OTHER", f"bytes={b.hex()}"
    cat[c] += 1
    out.write(f"{rva:#x}\t{c}\t{d}\n")
out.close()
print(dict(cat))
