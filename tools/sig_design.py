# sig_design.py - 离线设计并验证 5 钩特征签名
# 方法：对每个钩子取老/新 GA 各自 RVA 处 N 字节 -> 逐位 diff 生成掩码 ->
#       在两份 GA 的 .text 全量扫描掩码命中，要求：期望 RVA 命中且总数可控（唯一）
import pefile, sys, re

# 支持命令行覆盖：sig_design.py [old.dll new.dll oldRVA newRVA [tag]]
if len(sys.argv) >= 6:
    OLD, NEW = sys.argv[1], sys.argv[2]
    HOOKS = {sys.argv[5]: (int(sys.argv[3],16), int(sys.argv[4],16))}
else:
    OLD = r"c:\workspace\9-4#2\tools\GameAssembly_old_0902.dll"
    NEW = r"c:\workspace\9-4#2\tools\GameAssembly.dll"
    HOOKS = {"V": (0x11BE640, 0x12144F0), "I": (0x11BE670, 0x1214940),
             "C": (0x11BEF10, 0x1215270), "D": (0x1049B70, 0x10D74B0),
             "U": (0x1660650, 0x14DB0B0)}
N = 24

def load(path):
    pe = pefile.PE(path, fast_load=True)
    data = pe.__data__
    # 钩子位于 il2cpp 节（可执行代码主节）；.text 仅引导
    secs = [(s.VirtualAddress, s.PointerToRawData, s.SizeOfRawData) for s in pe.sections
            if s.Name.rstrip(b"\x00") in (b"il2cpp", b".text")]
    return pe, data, secs

def rva2off(secs, rva):
    for va, pr, sz in secs:
        if va <= rva < va + sz: return pr + (rva - va)
    return None

def scan(secs, data, mask):
    """mask: list of int or None(通配)。返回命中的 RVA 列表（全部候选节）"""
    hits = []
    n = len(mask)
    first = next((i for i,b in enumerate(mask) if b is not None), 0)
    import re
    for va, pr, sz in secs:
        blob = data[pr:pr+sz]
        fb = bytes([mask[first]])
        for m in re.finditer(re.escape(fb), blob):
            p = m.start() - first
            if p < 0 or p + n > sz: continue
            ok = True
            for i, b in enumerate(mask):
                if b is not None and blob[p+i] != b: ok = False; break
            if ok: hits.append(va + p)
    return hits

po, do, so = load(OLD)
pn, dn, sn = load(NEW)

for L, (ro, rn) in HOOKS.items():
    oo = rva2off(so, ro); on = rva2off(sn, rn)
    best = None
    for N in (16, 24, 32, 48, 64, 96, 128, 192, 256, 384, 512):
        bo = do[oo:oo+N]; bn = dn[on:on+N]
        if len(bo) < N or len(bn) < N: break
        mask = [None if a != b else a for a, b in zip(bo, bn)]
        ms = " ".join("?" if m is None else f"{m:02X}" for m in mask)
        ho = scan(so, do, mask); hn = scan(sn, dn, mask)
        both_ok = (ro in ho and rn in hn)
        if not best: best = (N, ms, len(ho), len(hn), both_ok)
        # 两版都唯一且命中 -> 停止加长
        if len(ho) == 1 and len(hn) == 1 and both_ok:
            best = (N, ms, 1, 1, True); break
    N, ms, co, cn, ok = best
    print(f"{L}: len={N} old_hits={co} new_hits={cn} both_expect={'OK' if ok else 'MISS'}")
    print(f"   {ms}")
    open(rf"c:\workspace\9-4#2\implant\sig_{L}.txt", "w").write(ms)


