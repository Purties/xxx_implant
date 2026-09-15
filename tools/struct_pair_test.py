# struct_pair_test.py - 测试结构配对可行性：
# 1) dispatch_identity 的老类哈希是否存在于 implant/out/methods.tsv（判定是否同构建导出）
# 2) 若是：老类结构(方法数+params多重集) 与 b2 类结构做 join，看 5 钩所在类能否唯一配对
import collections, hashlib
IDENT = r"c:\workspace\9-4#2\xxx\analysis\dispatch_identity.tsv"
OLDDUMP = r"c:\workspace\9-4#2\implant\out\methods.tsv"
B2DUMP  = r"c:\workspace\9-4#2\xxx\analysis\methods_new_0915.tsv"

def load_dump(p):
    cls = collections.defaultdict(list)  # class -> [(method, params, rva)]
    with open(p, encoding="utf-8", errors="replace") as f:
        f.readline()
        for line in f:
            r = line.rstrip("\n").split("\t")
            if len(r) >= 6:
                cls[r[3]].append((r[4], r[5], r[0]))
    return cls

old = load_dump(OLDDUMP); b2 = load_dump(B2DUMP)
idrows = [l.split("\t") for l in open(IDENT, encoding="utf-8").read().splitlines()[1:]]
res = [r for r in idrows if len(r)>=6 and r[1]=="RESOLVED"]
present = sum(1 for r in res if r[3].lstrip(".") in old)
print(f"identity class hashes present in OLDDUMP: {present}/{len(res)}")
# 也检查 identity 方法哈希
mp = sum(1 for r in res if any(m[0]==r[4].lstrip(".") for m in old.get(r[3].lstrip("."),[])))
print(f"identity (class,method) present in OLDDUMP: {mp}/{len(res)}")

# 类结构指纹 join: (方法数, params多重集, 方法名多重集)
def fp(methods): return (len(methods), tuple(sorted(int(p) if p.lstrip('-').isdigit() else 0 for _,p,_ in methods)), tuple(sorted(m for m,_,_ in methods)))
ofp = collections.defaultdict(list)
for c, ms in old.items(): ofp[fp(ms)].append(c)
bfp = collections.defaultdict(list)
for c, ms in b2.items(): bfp[fp(ms)].append(c)
HOOKCLS = {"V":"f46670bd6ea22817", "D":"ac815ae99e729e8e", "U":"b6be5581803c58bc"}
# 找 5 钩类的完整哈希（从 identity）
for r in res:
    for k,pre in HOOKCLS.items():
        if r[3].lstrip(".").startswith(pre): HOOKCLS[k]=r[3].lstrip(".")
for k,c in HOOKCLS.items():
    ms = old.get(c)
    if not ms: print(f"{k} class {c[:20]}: NOT in old dump"); continue
    f = fp(ms)
    cand = bfp.get(f, [])
    print(f"{k}: old class {c[:20]} methods={len(ms)} -> b2 structural matches: {len(cand)} {cand[:2]}")
