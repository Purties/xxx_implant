# targeted_probe.py - targeted skeleton search for critical VecCtrlMob hooks in new GA
NEW = r"C:\冒险岛online\mxdclassic\GameAssembly.dll"
new = open(NEW, "rb").read()
NEW_RAW0, NEW_RAW1, NEW_VA0 = 0x488400, 0x488400 + 0x4efb600, 0x489000

def find_all(needle):
    out = []
    s = NEW_RAW0
    while True:
        i = new.find(needle, s, NEW_RAW1)
        if i < 0:
            break
        out.append(NEW_VA0 + (i - NEW_RAW0))
        s = i + 1
    return out

# 1) velocity writer core: mov [rcx+0xf8], rdx  = 48 89 91 f8 00 00 00
print("mov [rcx+0xf8],rdx :", [hex(x) for x in find_all(bytes.fromhex("48 89 91 f8 00 00 00"))][:20])
# with the following movzx eax, [rip+..] opcode prefix: 48 89 91 f8 00 00 00 0f b6 05
print("..+movzx eax,[rip]:", [hex(x) for x in find_all(bytes.fromhex("48 89 91 f8 00 00 00 0f b6 05"))][:20])
# full-ish skeleton: 48 89 91 f8 00 00 00 0f b6 05 ?? ?? ?? ?? ?? 82? (add al,imm8 masked -> wildcard unknown)
# try: mov [rcx+0xf4], al after add:  88 81 f4 00 00 00
print("mov [rcx+0xf4],al :", [hex(x) for x in find_all(bytes.fromhex("88 81 f4 00 00 00"))][:20])

# 2) 0x11bef10 function: sub rsp,48 / lea rax,[rip+74] / mov [rsp+40],rax / mov rax,[rsp+40] / mov [rip+..],rax
#    skeleton: 48 83 ec ?? 48 8d 05 ?? ?? ?? ?? 48 89 44 24 ?? 48 8b 44 24 ?? 48 89 05
import re
pat = bytes.fromhex("48 83 ec")
hits = []
s = NEW_RAW0
skel = [0x48,0x83,0xec,None,0x48,0x8d,0x05,None,None,None,None,0x48,0x89,0x44,0x24,None,0x48,0x8b,0x44,0x24,None,0x48,0x89,0x05]
L = len(skel)
while True:
    i = new.find(pat, s, NEW_RAW1)
    if i < 0:
        break
    if all(skel[k] is None or new[i+k] == skel[k] for k in range(L)):
        hits.append(NEW_VA0 + (i - NEW_RAW0))
    s = i + 1
print("0x11bef10 skeleton hits:", [hex(x) for x in hits][:20], f"(n={len(hits)})")
