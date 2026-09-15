# hash_stability_test.py - 决定性测试：混淆类/方法哈希是否跨构建稳定？
# 用 5 钩已知 (old_rva -> b2_rva) 对：
#   old 侧身份来自 dispatch_identity.tsv（老版运行时枚举）
#   b2  侧身份来自 methods_new_0915.tsv（b2 运行时枚举）
# 若同一方法的 (class_hash, method_hash) 在两版相同 -> 哈希由原始名决定、跨构建稳定 -> 可全表 hash-join
import sys
IDENT = r"c:\workspace\9-4#2\xxx\analysis\dispatch_identity.tsv"
B2    = r"c:\workspace\9-4#2\xxx\analysis\methods_new_0915.tsv"
HOOK = {"V":(0x11BE640,0x12144F0),"I":(0x11BE670,0x1214940),"C":(0x11BEF10,0x1215270),
        "D":(0x1049B70,0x10D74B0),"U":(0x1660650,0x14DB0B0)}

# old identities
idrows=[l.split("\t") for l in open(IDENT,encoding="utf-8").read().splitlines()[1:]]
old={r[0].lower():r for r in idrows if len(r)>=6}
# b2 identities by rva
b2={}
with open(B2,encoding="utf-8",errors="replace") as f:
    f.readline()
    for line in f:
        r=line.rstrip("\n").split("\t")
        if len(r)>=6: b2[r[0].lower()]=r
print("tag | old cls/mtd hash            | b2 cls/mtd hash               | stable?")
stable=0
for k,(ro,rn) in HOOK.items():
    o=old.get(hex(ro).lower()); n=b2.get(hex(rn).lower())
    if not o or not n:
        print(f"{k}: old={'Y' if o else 'N'} b2={'Y' if n else 'N'} (missing)"); continue
    oc=o[3].lstrip('.'); om=o[4]; nc=n[3]; nm=n[4]
    s = (oc==nc and om==nm); stable+=s
    print(f"{k} | {oc[:16]}/{om[:16]} | {nc[:16]}/{nm[:16]} | {'SAME' if s else 'DIFF'}")
print(f"\nhash-stable across builds: {stable}/5")
print("=> SAME: 可 hash-join 全表配对（离线批量生成签名可行）")
print("=> DIFF: 哈希逐构建轮换（与项目记忆一致），未配对目标无法离线 bootstrap")
