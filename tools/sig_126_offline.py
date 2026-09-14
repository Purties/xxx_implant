# sig_126_offline.py - 离线用特征签名把全 126 dispatch RVA 映射到新版
# 流程：老版每个 RVA 取字节 -> 自动加长到"老版唯一" -> 用该签名扫新版 ->
#       新版唯一命中即预测新 RVA；与已知真值（rva_migration.tsv new 列 + 5 钩）比对。
#
# ⚠ 结论（2026-09-14 实测）：本脚本用【全精确字节】掩码，跨构建时 RIP disp32/
#   imm8 混淆常量必然轮换 -> 新版命中要么 0 要么歧义，实测与 rva_migration.tsv
#   （已掩码化的字节管线）一致：仅 ~24/126 可离线唯一，5 钩中仅 D 可离线覆盖。
#   => 纯离线字节法存在天花板；其余目标必须走 implant 运行时结构签名 + 约束消歧
#      （已活体证明 5/5 UNIQUE-MATCH，见 UNPACKING_REPORT §5.9.5b）。保留本脚本
#   作为"离线可解析子集"的生成器（这部分零成本白拿）。
import pefile, re, collections

OLD = r"c:\workspace\9-4#2\tools\GameAssembly_old_0902.dll"
NEW = r"c:\workspace\9-4#2\tools\GameAssembly.dll"
MIG = r"c:\workspace\9-4#2\xxx\analysis\rva_migration.tsv"
OUT = r"c:\workspace\9-4#2\xxx\analysis\sig126_offline.tsv"

def load(path):
    pe = pefile.PE(path, fast_load=True)
    secs = [(s.VirtualAddress, s.PointerToRawData, s.SizeOfRawData) for s in pe.sections
            if s.Name.rstrip(b"\x00") in (b"il2cpp", b".text")]
    return pe.__data__, secs
def rva2off(secs, rva):
    for va, pr, sz in secs:
        if va <= rva < va + sz: return pr + (rva - va)
    return None
_pat_cache = {}
def scan(secs, data, mask):
    """把掩码编译成 bytes 正则（. 通配），C 级匹配速度"""
    key = tuple(mask)
    pat = _pat_cache.get(key)
    if pat is None:
        pat = re.compile(b"".join(b"." if m is None else re.escape(bytes([m])) for m in mask), re.DOTALL)
        _pat_cache[key] = pat
    hits = []
    for va, pr, sz in secs:
        blob = data[pr:pr+sz]
        for m in pat.finditer(blob):
            hits.append(va + m.start())
    return hits

do, so = load(OLD); dn, sn = load(NEW)

# 已知真值：rva_migration.tsv 第 2 列（new_rva）非空者 + 5 钩
truth = {}
rows = [l.split("\t") for l in open(MIG, encoding="utf-8").read().splitlines()[1:]]
for r in rows:
    if len(r) >= 2 and r[1].strip().startswith("0x"):
        truth[int(r[0],16)] = int(r[1],16)
for o,n in {"V":(0x11BE640,0x12144F0),"I":(0x11BE670,0x1214940),"C":(0x11BEF10,0x1215270),
            "D":(0x1049B70,0x10D74B0),"U":(0x1660650,0x14DB0B0)}.items():
    truth[o]=n

old_rvas = sorted({int(r[0],16) for r in rows if r and r[0].startswith("0x")})
print(f"old dispatch RVAs: {len(old_rvas)}, ground-truth new RVAs known: {len(truth)}")

out = open(OUT, "w", encoding="utf-8")
out.write("old_rva\tnew_rva_pred\tsig_len\tnew_hits\tstatus\ttruth\n")
cat = collections.Counter()
for ro in old_rvas:
    oo = rva2off(so, ro)
    if oo is None: cat["no-old-bytes"]+=1; out.write(f"{ro:#x}\t\t\t\tNO_OLD_BYTES\t\n"); continue
    pred=None; slen=0; nhits=0
    for N in (16,24,32,48,64,96,128,192,256):
        if oo+N > len(do): break
        bo = do[oo:oo+N]
        # 老版唯一化：先用"全精确"签名，若老版不唯一则加长；老版唯一后扫新版
        mask = list(bo)
        ho = scan(so, do, mask)
        if len(ho) != 1: continue
        hn = scan(sn, dn, mask)
        slen = N; nhits = len(hn)
        if len(hn) == 1:
            pred = hn[0]; break
    if pred is not None:
        t = truth.get(ro)
        if t is None: st = "PREDICTED(no-truth)"
        elif t == pred: st = "PREDICT-CORRECT"
        else: st = "PREDICT-WRONG"
        cat[st]+=1
        out.write(f"{ro:#x}\t{pred:#x}\t{slen}\t{nhits}\t{st}\t{t if t else ''}\n")
    elif nhits == 0:
        cat["new-not-found"]+=1
        out.write(f"{ro:#x}\t\t{slen}\t0\tNEW-NOT-FOUND\t{truth.get(ro,'')}\n")
    else:
        cat["new-ambiguous"]+=1
        out.write(f"{ro:#x}\t\t{slen}\t{nhits}\tNEW-AMBIGUOUS\t{truth.get(ro,'')}\n")
out.close()
print("categories:", dict(cat))
correct = cat["PREDICT-CORRECT"]; wrong = cat["PREDICT-WRONG"]
if correct+wrong: print(f"accuracy on known-truth: {correct}/{correct+wrong}")
