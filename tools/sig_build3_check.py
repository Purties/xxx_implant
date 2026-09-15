# sig_build3_check.py - 用 implant 的 5 条签名离线扫描第三构建 GA，验证跨构建可移植性
import pefile, re

B3 = r"D:\build3_backup\GameAssembly_build3.dll"

# 5 条签名掩码（与 implant.c g_sigs[] 一致；'?'=通配）
SIGS = {
 "V": "48 89 91 F8 00 00 00 0F B6 05 ? ? ? 05 ? ?",
 "I": "56 57 53 48 81 EC ? 01 00 00 44 0F 29 84 24 ? 01 00 00 0F 29 BC 24 ? 01 00 00 0F 29 B4 24 ? 01 00 00 66 0F 28 F2 66 0F 28 F9 48 89 CE 48 8D",
 "C": "48 83 EC ? 48 8D 05 ? 00 00 00 48 89 44 24 ? 48 8B 44 24 ? 48 89 05 ? ? ? 05 48 8D 05 ? 00 00 00 48 89 44 24 ? 48",
 "D": "41 57 41 56 41 55 41 54 56 57 55 53 B8 ? 12 00 00 E8 ? ? ? FF 48 29 C4 0F 29 BC 24 ? 12 00",
 "U": "E9 0B 00 00 00 66 66 2E 0F 1F 84 00 00 00 00 00 56 57 53 48 81 EC ? ? 00 00 48 89 CE 48 8D 05 ? ? 00 00 48 89 84 24 ? ? 00 00 48 8D 0D ?",
}
# 上一构建（ba7b80fc）已知 RVA，仅供参考对比
PREV = {"V":0x12144F0,"I":0x1214940,"C":0x1215270,"D":0x10D74B0,"U":0x14DB0B0}

pe = pefile.PE(B3, fast_load=True)
data = pe.__data__
secs = [(s.VirtualAddress, s.PointerToRawData, s.SizeOfRawData) for s in pe.sections
        if s.Name.rstrip(b"\x00") in (b"il2cpp", b".text")]

def to_mask(m):
    out=[]
    for tok in m.split():
        out.append(None if tok=='?' else int(tok,16))
    return out
def scan(mask):
    pat = re.compile(b"".join(b"." if b is None else re.escape(bytes([b])) for b in mask), re.DOTALL)
    hits=[]
    for va,pr,sz in secs:
        blob=data[pr:pr+sz]
        for mm in pat.finditer(blob): hits.append(va+mm.start())
    return hits

print("build3 GA:", B3)
print("tag  hits  rva_found        prev_ba7b80fc")
ok=0
for t,m in SIGS.items():
    h=scan(to_mask(m))
    r = f"{h[0]:#x}" if len(h)==1 else f"{len(h)}hits"
    if len(h)==1: ok+=1
    print(f"{t}   {len(h):3d}   {r:16s}   {PREV[t]:#x}")
print(f"\nUNIQUE on build3: {ok}/5")
print("=> 若 5/5 唯一：特征签名法跨第三构建成立，游戏更新无需人工维护（架构实战检验通过）")
print("=> 若某钩子多命中/0命中：该钩子签名需在新构建现场用结构约束消歧（race 注入跑 implant 即可）")
