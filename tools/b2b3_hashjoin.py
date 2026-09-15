# b2b3_hashjoin.py - 验证 b2<->b3 方法级哈希稳定性并生成全量对应表
# 背景：name_style_check 显示 b2/b3 类哈希交集 9340/11462(81%)；old->b2 哈希轮换(0/5)。
# 若 (class,method) 对在 b2/b3 间稳定，hash-join 直接得 b2_rva<->b3_rva 全量映射。
import collections
B2 = r"c:\workspace\9-4#2\xxx\analysis\methods_new_0915.tsv"   # ba7b80fc
B3 = r"c:\workspace\9-4#2\implant\out\methods.tsv"             # 0c06cc8c

def load(p):
    rows=[]
    with open(p,encoding="utf-8",errors="replace") as f:
        f.readline()
        for line in f:
            r=line.rstrip("\n").split("\t")
            if len(r)>=6: rows.append(r)
    return rows

b2=load(B2); b3=load(B3)
k2=collections.defaultdict(list); k3=collections.defaultdict(list)
for r in b2: k2[(r[3],r[4],r[5])].append(r[0])   # (cls,mtd,params) -> rvas
for r in b3: k3[(r[3],r[4],r[5])].append(r[0])
inter=set(k2)&set(k3)
uniq=sum(1 for k in inter if len(k2[k])==1 and len(k3[k])==1)
print(f"b2 keys={len(k2)} b3 keys={len(k3)} intersect={len(inter)} unique-1:1={uniq}")
print(f"=> b2/b3 方法身份稳定率: {len(inter)}/{len(k2)} = {100*len(inter)//len(k2)}%")
# 5 钩 b2<->b3 校验
HOOKB2B3={"V":(0x12144F0,0x1217300),"I":(0x1214940,0x1217760),"C":(0x1215270,0x1218010),
          "D":(0x10D74B0,0x10DA940),"U":(0x14DB0B0,0x14DD460)}
r2i={r[0].lower():r for r in b2}; r3i={r[0].lower():r for r in b3}
ok=0
for k,(a,b) in HOOKB2B3.items():
    ra=r2i.get(hex(a)); rb=r3i.get(hex(b))
    same = ra and rb and (ra[3],ra[4],ra[5])==(rb[3],rb[4],rb[5])
    ok+=bool(same)
    print(f"  {k}: b2 {(ra[3][:12],ra[4][:12]) if ra else '?'} <-> b3 {(rb[3][:12],rb[4][:12]) if rb else '?'} {'SAME' if same else 'DIFF'}")
print(f"5-hook b2<->b3 identity identical: {ok}/5")
# 生成 1:1 对应表
out=open(r"c:\workspace\9-4#2\xxx\analysis\b2b3_map.tsv","w",encoding="utf-8")
out.write("b2_rva\tb3_rva\tclass\tmethod\tparams\n")
n=0
for k in inter:
    if len(k2[k])==1 and len(k3[k])==1:
        out.write(f"{k2[k][0]}\t{k3[k][0]}\t{k[0]}\t{k[1]}\t{k[2]}\n"); n+=1
out.close()
print(f"1:1 map written: {n} rows -> b2b3_map.tsv")
