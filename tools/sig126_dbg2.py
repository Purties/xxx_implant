# sig126_dbg2.py - 诊断 C/D 钩 diff 法逐 N 失败原因
import sys, os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import sig126_gen as G

old=G.GA(G.OLD); b2=G.GA(G.B2); b3=G.GA(G.B3)

def diff_mask(a,b): return [None if x!=y else x for x,y in zip(a,b)]

for k in ("C","D","V","I","U"):
    ro,r2,r3 = G.HOOK[k]
    flen_o=old.func_len(ro); flen_2=b2.func_len(r2); flen_3=b3.func_len(r3)
    print(f"\n[{k}] old rva={ro:#x} flen={flen_o:#x} | b2 {r2:#x} flen={flen_2:#x} | b3 {r3:#x} flen={flen_3:#x}")
    for N in (16,24,32,48,64,96,128,192,256):
        co=old.bytes_at(ro,N); cn=b2.bytes_at(r2,N)
        if not co or not cn or len(co)<N or len(cn)<N: print(f"  N={N}: short"); break
        m=diff_mask(co,cn)
        exact=sum(1 for b in m if b is not None)
        ho=G.scan(old,m); hn=G.scan(b2,m); h3=G.scan(b3,m)
        print(f"  N={N}: exact={exact} old={len(ho)}{'(OK)' if ho==[ro] else ho[:3]} b2={len(hn)}{'(OK)' if hn==[r2] else hn[:3]} b3={len(h3)}{'(OK)' if h3==[r3] else h3[:3]}")
        if len(ho)==1 and len(hn)==1 and len(h3)==1: break
