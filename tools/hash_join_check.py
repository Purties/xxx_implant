# hash_join_check.py - 检验：老版类哈希/方法哈希是否也存在于 b2 导出表
# 若存在 -> 混淆器哈希由原始名决定，跨构建稳定 -> (clsHash,mtdHash,params) 可直接配对
import sys
METHODS = r"c:\workspace\9-4#2\xxx\analysis\methods_new_0915.tsv"
IDENT = r"c:\workspace\9-4#2\xxx\analysis\dispatch_identity.tsv"

b2 = {}   # (cls, mtd) -> [(rva, params)]
with open(METHODS, encoding="utf-8", errors="replace") as f:
    f.readline()
    for line in f:
        p = line.rstrip("\n").split("\t")
        if len(p) < 6: continue
        b2.setdefault((p[3], p[4]), []).append((p[0], p[5]))

rows = [l.split("\t") for l in open(IDENT, encoding="utf-8").read().splitlines()[1:]]
res = [r for r in rows if len(r)>=6 and r[1]=="RESOLVED"]
hit = sum(1 for r in res if (r[3], r[4]) in b2)
print(f"RESOLVED old identities: {len(res)}, class+method hash pair found in b2 export: {hit}")
for r in res[:8]:
    k = (r[3], r[4])
    print(f"  {r[0]} params={r[5]} in_b2={k in b2} {b2.get(k)}")
