# gen_sigs126_c.py - 从 sig126_paired.tsv 生成 implant.c 的 g_sigs126[] 数组
import sys
rows=[l.split("\t") for l in open(r"c:\workspace\9-4#2\xxx\analysis\sig126_paired.tsv",encoding="utf-8").read().splitlines()[1:]]
out=[]
out.append("/* 21 条三构建唯一签名（0902/ba7b80fc/0c06cc8c 离线 diff 生成，三版各自唯一命中）")
out.append(" * 生成器: tools/sig126_paired.py；tag=老版 RVA；expect=第三构建 RVA；")
out.append(" * 匹配方式: 静态扫描 GA 映像 il2cpp/.text 节字节（含函数体内目标，不依赖方法枚举） */")
out.append("static struct sig g_sigs126[] = {")
n=0
for r in rows:
    if len(r)<6 or r[5].strip()!="3BUILD-UNIQUE": continue
    ro,b2,b3,mask,l=r[0],r[1],r[2],r[3],int(r[4])
    esc=mask.replace('"','')
    out.append(f'    {{ "{ro[2:]}", "{esc}", {l}, {ro}, {b3 if b3 else "0"}, -1, NULL, NULL, 0, NULL, NULL }},')
    n+=1
out.append("};")
out.append(f"#define NSIGS126 {n}")
txt="\n".join(out)
open(r"c:\workspace\9-4#2\implant\sigs126.inc","w",encoding="utf-8").write(txt)
print(txt[:800]); print("..."); print(f"total: {n}")
