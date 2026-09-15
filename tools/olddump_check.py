# olddump_check.py - 检查老版运行时导出 dump 的来源与覆盖
import re
d = open(r"c:\workspace\9-4#2\implant\out\methods.tsv", encoding="utf-8", errors="replace").read().splitlines()
print("rows:", len(d))
print("first:", d[1])
print("last :", d[-1])
rvas = [int(l.split("\t")[0], 16) for l in d[1:] if re.match(r"0x[0-9a-fA-F]+$", l.split("\t")[0])]
print("min rva", hex(min(rvas)), "max rva", hex(max(rvas)))
for t in (0x11BE640, 0x11BE670, 0x11BEF10, 0x1049B70, 0x1660650):
    print(f"has {t:#x}:", t in rvas)
# 老版导出里这些类哈希的样本
print("sample class col:", d[1].split("\t")[3])
