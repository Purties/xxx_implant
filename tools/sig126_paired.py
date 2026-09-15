# sig126_paired.py - 对全部有 (old,b2) 真值对的目标跑双版 diff，用 b3 做第三方独立校验
# 目的：量化"纯离线 diff 法"的真实天花板（多少签名能三版唯一）
import sys, os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import sig126_gen as G

old=G.GA(G.OLD); b2=G.GA(G.B2); b3=G.GA(G.B3)
def diff_mask(a,b): return [None if x!=y else x for x,y in zip(a,b)]

# 收集所有 (old,b2) 对
migrows=[l.split("\t") for l in open(G.MIG,encoding="utf-8").read().splitlines()[1:]]
pairs={int(r[0],16):int(r[1],16) for r in migrows if len(r)>=2 and r[1].strip().startswith("0x")}
for k,(ro,r2,_) in G.HOOK.items(): pairs[ro]=r2
print(f"targets with (old,b2) pair: {len(pairs)}")

out=open(r"c:\workspace\9-4#2\xxx\analysis\sig126_paired.tsv","w",encoding="utf-8")
out.write("old_rva\tb2_rva\tb3_rva\tmask\tlen\tstatus\n")
ok=b3miss=b3amb=0
for ro,rn in sorted(pairs.items()):
    res=None
    for N in (16,24,32,48,64,96,128,192,256):
        co=old.bytes_at(ro,N); cn=b2.bytes_at(rn,N)
        if not co or not cn or len(co)<N or len(cn)<N: break
        m=diff_mask(co,cn)
        if sum(1 for b in m if b is not None)<8: continue
        ho=G.scan(old,m); hn=G.scan(b2,m); h3=G.scan(b3,m)
        if len(ho)==1 and ho[0]==ro and len(hn)==1 and hn[0]==rn and len(h3)==1:
            res=(N,m,h3[0],"3BUILD-UNIQUE"); break
        if len(ho)==1 and len(hn)==1 and (len(h3)==0 or len(h3)>1):
            res=(N,m,h3[0] if h3 else None, "b3-"+("MISS" if len(h3)==0 else f"AMBIG{len(h3)}"))
    if res and res[3]=="3BUILD-UNIQUE":
        ok+=1; N,m,r3,st=res
        ms=" ".join("?" if b is None else f"{b:02X}" for b in m)
        out.write(f"{ro:#x}\t{rn:#x}\t{r3:#x}\t{ms}\t{N}\t{st}\n")
    elif res:
        N,m,r3,st=res
        if "MISS" in st: b3miss+=1
        else: b3amb+=1
        out.write(f"{ro:#x}\t{rn:#x}\t{r3 and hex(r3) or ''}\t\t{N}\t{st}\n")
    else:
        out.write(f"{ro:#x}\t{rn:#x}\t\t\t\tNO-UNIQ\n")
out.close()
print(f"3-build unique (usable offline): {ok}/{len(pairs)}   b3-miss: {b3miss}   b3-ambig: {b3amb}")
print("=> 仅 3-build-unique 的签名可纯离线交付；其余需活体结构约束（同 5 钩 C/D 现状）")
