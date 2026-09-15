# sig126_dbg.py - 对比 5 钩：启发式生成掩码 vs 已知 good diff 掩码 vs 老/新真实字节
import sys, os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import sig126_gen as G

old=G.GA(G.OLD); b2=G.GA(G.B2); b3=G.GA(G.B3)
KNOWN={
 "V":"48 89 91 F8 00 00 00 0F B6 05 ? ? ? 05 ? ?",
 "I":"56 57 53 48 81 EC ? 01 00 00 44 0F 29 84 24 ? 01 00 00 0F 29 BC 24 ? 01 00 00 0F 29 B4 24 ? 01 00 00 66 0F 28 F2 66 0F 28 F9 48 89 CE 48 8D",
 "C":"48 83 EC ? 48 8D 05 ? 00 00 00 48 89 44 24",
 "D":"41 57 41 56 41 55 41 54 56 57 55 53 B8 ? ? ? ? E8 ? ? ? FF 48 29 C4",
 "U":"E9 0B 00 00 00 66 66 2E 0F 1F 84 00 00 00 00 00 56 57 53 48 81 EC ? ? 00 00 48 89 CE 48 8D 05 ? ? 00 00 48 89 84 24 ? ? 00 00 48 8D 0D ?",
}
for k,(ro,r2,r3) in G.HOOK.items():
    code=old.bytes_at(ro,64)
    m=G.heuristic_mask(code,ro)
    gen=" ".join("?" if b is None else f"{b:02X}" for b in m)
    print(f"\n[{k}] old bytes@{ro:#x}: {' '.join(f'{b:02X}' for b in old.bytes_at(ro,24))}")
    print(f"  b2  bytes@{r2:#x}: {' '.join(f'{b:02X}' for b in b2.bytes_at(r2,24))}")
    print(f"  b3  bytes@{r3:#x}: {' '.join(f'{b:02X}' for b in b3.bytes_at(r3,24))}")
    print(f"  KNOWN-good: {KNOWN[k]}")
    print(f"  GEN      : {gen}")
    print(f"  gen hits b2={len(G.scan(b2,m))} b3={len(G.scan(b3,m))}")
