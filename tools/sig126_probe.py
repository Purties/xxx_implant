# sig126_probe.py - 盘点 126 dispatch 目标的可解析性
# 关键问题：sig_design.py 的自动掩码法需要 (oldRVA,newRVA) 一对做逐位 diff。
#   5 钩有真值对；其余 121 个没有 old<->new 对应，无法 bootstrap diff。
#   本脚本先量化：126 里有多少是方法入口、有多少已有 new 真值、
#   并测试"仅用老版字节 + 反汇编启发式通配"能否在 ba7b80fc / build3 上唯一命中（用 5 钩做已知答案校验）。
import pefile, re, collections, sys

OLD = r"c:\workspace\9-4#2\tools\GameAssembly_old_0902.dll"
B2  = r"c:\workspace\9-4#2\tools\GameAssembly.dll"                 # ba7b80fc
B3  = r"D:\build3_backup\GameAssembly_build3.dll"                  # 0c06cc8c
MIG = r"c:\workspace\9-4#2\xxx\analysis\rva_migration.tsv"
IDENT = r"c:\workspace\9-4#2\xxx\analysis\dispatch_identity.tsv"

def load(path):
    pe = pefile.PE(path, fast_load=True)
    secs = [(s.VirtualAddress, s.PointerToRawData, s.SizeOfRawData) for s in pe.sections
            if s.Name.rstrip(b"\x00") in (b"il2cpp", b".text")]
    return pe.__data__, secs

def rva2off(secs, rva):
    for va, pr, sz in secs:
        if va <= rva < va + sz: return pr + (rva - va)
    return None

def pdata(path):
    import struct
    data = open(path, "rb").read()
    nt = struct.unpack_from("<I", data, 0x3C)[0]
    n = struct.unpack_from("<H", data, nt+6)[0]; osz = struct.unpack_from("<H", data, nt+0x14)[0]
    so = nt+0x18+osz
    secs = {}
    for i in range(n):
        s = so + i*0x28
        name = data[s:s+8].rstrip(b"\x00").decode("ascii","replace")
        va, vs, rs, rp = struct.unpack_from("<IIII", data, s+8)
        secs[name] = (va, vs, rp, rs)
    va, vs, rp, rs = secs[".pdata"]
    ent = []
    for off in range(rp, rp+rs, 12):
        b, e, u = struct.unpack_from("<III", data, off)
        ent.append((b, e))
    ent.sort()
    return ent

def func_len(ent, rva):
    import bisect
    begins = [e[0] for e in ent]
    i = bisect.bisect_right(begins, rva) - 1
    if i < 0: return None
    b, e = ent[i]
    return (e - b) if b <= rva < e else None

# ---- 盘点 ----
rows = [l.split("\t") for l in open(MIG, encoding="utf-8").read().splitlines()[1:]]
old_rvas = sorted({int(r[0],16) for r in rows if r and r[0].startswith("0x")})
truth = {int(r[0],16): int(r[1],16) for r in rows if len(r)>=2 and r[1].strip().startswith("0x")}
idrows = [l.split("\t") for l in open(IDENT, encoding="utf-8").read().splitlines()[1:]]
status = {r[0]: r[1] for r in idrows if r}

print(f"old dispatch RVAs: {len(old_rvas)}")
print(f"  with new-build ground-truth (rva_migration): {len(truth)}")
cnt = collections.Counter(status.get(f"{r:#x}", "ABSENT") for r in old_rvas)
print("  dispatch_identity status:", dict(cnt))

# 5 钩已知对（old -> b2 -> b3）
HOOK = {"V":(0x11BE640,0x12144F0,0x1217300), "I":(0x11BE670,0x1214940,0x1217760),
        "C":(0x11BEF10,0x1215270,0x1218010), "D":(0x1049B70,0x10D74B0,0x10DA940),
        "U":(0x1660650,0x14DB0B0,0x14DD460)}
print("\n5-hook ground truth (old/b2/b3):")
for k,(a,b,c) in HOOK.items():
    print(f"  {k}: {a:#x} / {b:#x} / {c:#x}")
