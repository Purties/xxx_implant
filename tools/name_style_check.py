# name_style_check.py - 对比老版导出(implant/out/methods.tsv)与 b2 导出(methods_new_0915.tsv)的类/方法名风格
import re
OLD = r"c:\workspace\9-4#2\implant\out\methods.tsv"
B2  = r"c:\workspace\9-4#2\xxx\analysis\methods_new_0915.tsv"

def load(p):
    rows = []
    with open(p, encoding="utf-8", errors="replace") as f:
        f.readline()
        for line in f:
            r = line.rstrip("\n").split("\t")
            if len(r) >= 6: rows.append(r)
    return rows

old = load(OLD); b2 = load(B2)
print("old rows:", len(old), " b2 rows:", len(b2))
hl = lambda s: bool(re.fullmatch(r"[0-9a-f]{60,66}", s))
print("old hash-like classes: %d/%d   b2 hash-like classes: %d/%d" % (
    sum(hl(r[3]) for r in old), len(old), sum(hl(r[3]) for r in b2), len(b2)))
print("old hash-like methods: %d   b2 hash-like methods: %d" % (
    sum(hl(r[4]) for r in old), sum(hl(r[4]) for r in b2)))
oc = {r[3] for r in old}; bc = {r[3] for r in b2}
inter = oc & bc
print("class-name intersection:", len(inter), "/", len(oc), "vs", len(bc))
# 老版 identity 表中的类哈希是否出现在老版自身导出（验证 OLD tsv 与 identity 同一构建）
idrows = [l.split("\t") for l in open(r"c:\workspace\9-4#2\xxx\analysis\dispatch_identity.tsv", encoding="utf-8").read().splitlines()[1:]]
res = [r for r in idrows if len(r) >= 6 and r[1] == "RESOLVED"]
inold = sum(1 for r in res if r[3].lstrip(".") in oc or r[3] in oc)
print("RESOLVED identity class hashes present in OLD export:", inold, "/", len(res))
print("old sample:", sorted(oc)[:3])
print("b2 sample:", sorted(bc)[:3])
