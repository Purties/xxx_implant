# check_tail_behind.py - for each candidate call site, look for dispatcher tail pattern behind it
import sys

NEW = r"C:\冒险岛online\mxdclassic\GameAssembly.dll"
data = open(NEW, "rb").read()
RAW0, VA0 = 0x488400, 0x489000

pats = {
    "cmovne r8,rdx;jmp[r8]": bytes.fromhex("4c 0f 45 c2 41 ff 20"),
    "movzx edx,[rax+0x10]": bytes.fromhex("0f b6 50 10"),
}
for site in [int(a, 16) for a in sys.argv[1:]]:
    raw = RAW0 + (site - VA0)
    lo = raw - 0x300
    print(f"site {site:#x}:")
    for name, pat in pats.items():
        hits = []
        s = lo
        while True:
            i = data.find(pat, s, raw + 0x40)
            if i < 0:
                break
            hits.append(hex(VA0 + (i - RAW0)))
            s = i + 1
        print(f"   {name}: {hits}")
