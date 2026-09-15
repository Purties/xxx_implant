# sig126_pairgen.py - 为 33 个无真值对的 RESOLVED 目标挖掘 b2/b3 对应，再用双版 diff 法生成签名
#
# 流程（每个目标 old_rva，params 来自 dispatch_identity.tsv）：
#  1) 取老版序言骨架（启发式通配后的精确字节，仅用于粗筛，不作最终签名）
#  2) 在 b2 的 .pdata 函数表中，找骨架命中且函数长度相近、且 methods_new_0915 中
#     该方法 params 相符的候选（通常 1~3 个）
#  3) 对每个候选 (old, b2cand) 跑 sig_design 同款逐字节 diff -> 掩码
#  4) 判据（与 5 钩同标准）：掩码在老版唯一命中 old_rva、b2 唯一命中 b2cand、
#     b3 唯一命中（b3 无真值，唯一即视为解析成功）；三条件同时满足 -> 采纳
#  5) 输出 sig126.tsv：old_rva, b2_rva, b3_rva, mask, len
import sys, os, re, struct, bisect, collections
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import sig126_gen as G

METHODS = r"c:\workspace\9-4#2\xxx\analysis\methods_new_0915.tsv"

# ---- b2 方法入口表（methods_new_0915.tsv 是 b2 运行时枚举导出）----
def load_b2_entries():
    """rva -> params（GameAssembly 映像方法；tsv 列: rva image ns class name params）"""
    ent = {}
    with open(METHODS, encoding="utf-8", errors="replace") as f:
        head = f.readline()
        for line in f:
            p = line.rstrip("\n").split("\t")
            if len(p) < 6: continue
            try: rva = int(p[0], 16)
            except ValueError: continue
            try: pr = int(p[5])
            except ValueError: pr = -1
            ent[rva] = pr
    return ent

def skeleton(code, rva):
    """启发式通配后的骨架（粗筛用）：RIP disp32、大 imm32、小 imm32 低字节通配"""
    from capstone.x86 import X86_REG_RIP
    from capstone import Cs, CS_ARCH_X86, CS_MODE_64
    md = Cs(CS_ARCH_X86, CS_MODE_64); md.detail = True
    mask = [b for b in code]
    for ins in md.disasm(code, rva):
        if ins.address + ins.size > rva + len(code): break
        for op in ins.operands:
            if op.type == 3 and op.mem.base == X86_REG_RIP and op.mem.index == 0:
                off = ins.address - rva + ins.size - 4
                if 0 <= off and off + 4 <= len(mask):
                    for k in range(4): mask[off+k] = None
                break
        for op in ins.operands:
            if op.type == 2:
                v = op.imm & 0xFFFFFFFF
                vb = struct.pack("<I", v)
                base = ins.address - rva
                idx = code.find(vb, base, base + ins.size)
                if idx < 0: continue
                if v >= 0x100000 and (v >> 24) != 0:
                    for k in range(4): mask[idx+k] = None
                elif 0 < v < 0x100000:
                    mask[idx] = None
    return mask

_pat = {}
def scan(ga, mask):
    key = tuple(mask)
    pat = _pat.get(key)
    if pat is None:
        pat = re.compile(b"".join(b"." if m is None else re.escape(bytes([m])) for m in mask), re.DOTALL)
        _pat[key] = pat
    hits = []
    for va, pr, sz in ga.secs:
        for m in pat.finditer(ga.data[pr:pr+sz]): hits.append(va + m.start())
    return hits

def diff_mask(a, b):
    return [None if x != y else x for x, y in zip(a, b)]

def main():
    old = G.GA(G.OLD); b2 = G.GA(G.B2); b3 = G.GA(G.B3)
    b2ent = load_b2_entries()
    print(f"b2 method entries: {len(b2ent)}")

    idrows = [l.split("\t") for l in open(G.IDENT, encoding="utf-8").read().splitlines()[1:]]
    resolved = {int(r[0],16): int(r[5]) for r in idrows if len(r)>=6 and r[1]=="RESOLVED"}
    migrows = [l.split("\t") for l in open(G.MIG, encoding="utf-8").read().splitlines()[1:]]
    mig = {int(r[0],16): int(r[1],16) for r in migrows if len(r)>=2 and r[1].strip().startswith("0x")}
    for k,(ro,r2,_) in G.HOOK.items(): mig[ro] = r2   # 5 钩并入真值

    targets = sorted(ro for ro in resolved if ro not in mig)
    print(f"targets without (old,b2) pair: {len(targets)}")

    out = open(G.OUT, "w", encoding="utf-8")
    out.write("old_rva\tb2_rva\tb3_rva\tmask\tstatus\tparams\n")
    cat = collections.Counter()

    # 5 钩回归自检（diff 法应复现 RESOLVED）
    print("\n=== self-test: 5 hooks via diff method ===")
    for k,(ro,r2,r3) in G.HOOK.items():
        best = None
        for N in (16,24,32,48,64,96,128,192,256):
            co = old.bytes_at(ro, N); cn = b2.bytes_at(r2, N)
            if not co or not cn or len(co) < N or len(cn) < N: break
            m = diff_mask(co, cn)
            ho, hn, h3 = scan(old, m), scan(b2, m), scan(b3, m)
            if len(ho)==1 and ho[0]==ro and len(hn)==1 and hn[0]==r2 and len(h3)==1 and h3[0]==r3:
                best = (N, m); break
        print(f"  {k}: {'PASS len=%d'%best[0] if best else 'FAIL'}")

    # ---- 主流程 ----
    for ro in targets:
        params = resolved[ro]
        flen = old.func_len(ro)
        if flen is None:
            cat["no-pdata"] += 1; out.write(f"{ro:#x}\t\t\t\tno-pdata\t{params}\n"); continue
        # 候选挖掘：老版 24B 骨架在 b2 的命中 ∩ b2 方法入口(params 相符) ∩ 长度相近
        code = old.bytes_at(ro, min(24, flen))
        sk = skeleton(code, ro)
        if sum(1 for b in sk if b is not None) < 8:
            cat["weak-skel"] += 1; out.write(f"{ro:#x}\t\t\t\tweak-skel\t{params}\n"); continue
        sk_hits = scan(b2, sk)
        cands = [h for h in sk_hits
                 if h in b2ent and (params < 0 or b2ent[h] == params)
                 and b2.func_len(h) and abs(b2.func_len(h) - flen) <= max(64, flen//2)]
        if not cands:
            cat["no-cand"] += 1; out.write(f"{ro:#x}\t\t\t\tno-cand(skel %d hits)\t%d\n" % (len(sk_hits), params)); continue
        if len(cands) > 1:
            cat["multi-cand"] += 1
            out.write(f"{ro:#x}\t\t\t\tmulti-cand({','.join(hex(c) for c in cands[:5])})\t{params}\n"); continue
        rb = cands[0]
        # 双版 diff + 三版唯一校验
        done = False
        for N in (16,24,32,48,64,96,128,192,256):
            N = min(N, flen, b2.func_len(rb))
            co = old.bytes_at(ro, N); cn = b2.bytes_at(rb, N)
            if not co or not cn or len(co) < N or len(cn) < N: break
            m = diff_mask(co, cn)
            if sum(1 for b in m if b is not None) < 8: continue
            ho, hn, h3 = scan(old, m), scan(b2, m), scan(b3, m)
            if len(ho)==1 and ho[0]==ro and len(hn)==1 and hn[0]==rb and len(h3)==1:
                ms = " ".join("?" if b is None else f"{b:02X}" for b in m)
                cat["OK"] += 1
                out.write(f"{ro:#x}\t{rb:#x}\t{h3[0]:#x}\t{ms}\tOK\t{params}\n"); done = True; break
        if not done:
            cat["diff-not-unique"] += 1
            out.write(f"{ro:#x}\t{rb:#x}\t\t\tdiff-not-unique\t{params}\n")
    out.close()
    print("\ncategories:", dict(cat))
    print(f"output: {G.OUT}")

if __name__ == "__main__":
    main()
