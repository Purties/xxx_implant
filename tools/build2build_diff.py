# build2build_diff.py - 构建间 diff：b2 vs b3 真值对生成掩码 -> 在老版上验证泛化
# 假设：diff 通配的是"构建间会变的字节"，该假设与具体构建对无关 -> b2/b3 掩码应在老版命中
# 判据：掩码在 b2 唯一命中 b2_rva、b3 唯一命中 b3_rva、老版命中 old_rva（允许老版多命中，但须含 old_rva）
import sys, os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import sig126_gen as G

old=G.GA(G.OLD); b2=G.GA(G.B2); b3=G.GA(G.B3)
def diff_mask(a,b): return [None if x!=y else x for x,y in zip(a,b)]

print("=== build2-build3 diff, validated on OLD (generalization test) ===")
pass_=fail=0
for k,(ro,r2,r3) in G.HOOK.items():
    res=None
    for N in (16,24,32,48,64,96,128,192,256):
        cb=b2.bytes_at(r2,N); cc=b3.bytes_at(r3,N)
        if not cb or not cc or len(cb)<N or len(cc)<N: break
        m=diff_mask(cb,cc)
        if sum(1 for b in m if b is not None)<8: continue
        h2=G.scan(b2,m); h3=G.scan(b3,m); ho=G.scan(old,m)
        if len(h2)==1 and h2[0]==r2 and len(h3)==1 and h3[0]==r3:
            ok_old = (ro in ho)
            res=(N,len(ho),ok_old)
            if ok_old and len(ho)==1: break
    if res and res[2]:
        pass_+=1; print(f"  {k}: len={res[0]} old_hits={res[1]} -> GENERALIZES")
    else:
        fail+=1; print(f"  {k}: {'len=%d old_hits=%d NOT-in-old'%(res[0],res[1]) if res else 'FAIL'}")
print(f"generalization: {pass_}/5")
print("=> 5/5: b2/b3 对可解锁其余 42 个 RESOLVED 目标的离线 diff（无需再注入）")
print("=> <5/5: 构建间 diff 不泛化，未配对目标只能走活体结构约束")
