# runtime_name_join.py - 关键实验：运行时类/方法名是否跨构建稳定？
# 用 5 钩真值对 (old_rva -> b2_rva) 直接对比两份运行时导出的 (class, method)
import sys
OLD_DUMP = r"c:\workspace\9-4#2\implant\out\methods.tsv"      # 老版客户端运行时导出
B2_DUMP  = r"c:\workspace\9-4#2\xxx\analysis\methods_new_0915.tsv"

HOOK = {"V":(0x11BE640,0x12144F0), "I":(0x11BE670,0x1214940),
        "C":(0x11BEF10,0x1215270), "D":(0x1049B70,0x10D74B0),
        "U":(0x1660650,0x14DB0B0)}

def load(p):
    d = {}
    with open(p, encoding="utf-8", errors="replace") as f:
        f.readline()
        for line in f:
            r = line.rstrip("\n").split("\t")
            if len(r) >= 6:
                d.setdefault(r[0].lower(), []).append(r)
    return d

old = load(OLD_DUMP); b2 = load(B2_DUMP)
print("old dump entries:", sum(len(v) for v in old.values()), " b2 dump entries:", sum(len(v) for v in b2.values()))
print()
print("tag | old(class,method,params)            | b2(class,method,params)")
match = 0
for k,(ro,rn) in HOOK.items():
    o = old.get(hex(ro), []); n = b2.get(hex(rn), [])
    os_ = f"{o[0][3][:20]}.{o[0][4][:20]} p={o[0][5]}" if o else "NOT-IN-DUMP"
    ns_ = f"{n[0][3][:20]}.{n[0][4][:20]} p={n[0][5]}" if n else "NOT-IN-DUMP"
    same = bool(o and n and o[0][3]==n[0][3] and o[0][4]==n[0][4])
    match += same
    print(f"{k}  | {os_:42s} | {ns_:42s} | {'SAME' if same else 'DIFF'}")
print(f"\nruntime name identical across builds: {match}/5")
