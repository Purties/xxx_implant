# sig126_gen.py - 批量生成 47 个方法入口 dispatch 目标的跨构建掩码签名
#
# 背景：sig_design.py 的双版 diff 法需要 (oldRVA,newRVA) 真值对，仅 29 个目标有。
# 本脚本改用"单版启发式掩码"：反汇编老版序言，通配所有逐构建必然轮换的字段：
#   - RIP 相对寻址的 disp32（数据/代码布局每构建位移）
#   - imm32 落在元数据 token 区间 0x70______（metadata 重排即变）
#   - imm32/imm64 看起来像绝对/ RVA 地址（>0x400000 且非典型小常数）
# 校验集：5 钩（有 old/b2/b3 三版真值）。判据：启发式掩码在 b2、b3 上均唯一命中真值。
# 通过后再推广到其余 42 个 RESOLVED 目标，输出 sig126.tsv 供 implant 表生成。
import pefile, re, struct, bisect, sys, collections
from capstone import Cs, CS_ARCH_X86, CS_MODE_64

OLD = r"c:\workspace\9-4#2\tools\GameAssembly_old_0902.dll"
B2  = r"c:\workspace\9-4#2\tools\GameAssembly.dll"
B3  = r"D:\build3_backup\GameAssembly_build3.dll"
IDENT = r"c:\workspace\9-4#2\xxx\analysis\dispatch_identity.tsv"
MIG = r"c:\workspace\9-4#2\xxx\analysis\rva_migration.tsv"
OUT = r"c:\workspace\9-4#2\xxx\analysis\sig126.tsv"

HOOK = {"V":(0x11BE640,0x12144F0,0x1217300), "I":(0x11BE670,0x1214940,0x1217760),
        "C":(0x11BEF10,0x1215270,0x1218010), "D":(0x1049B70,0x10D74B0,0x10DA940),
        "U":(0x1660650,0x14DB0B0,0x14DD460)}

def load(path):
    pe = pefile.PE(path, fast_load=True)
    secs = [(s.VirtualAddress, s.PointerToRawData, s.SizeOfRawData) for s in pe.sections
            if s.Name.rstrip(b"\x00") in (b"il2cpp", b".text")]
    return pe.__data__, secs

def rva2off(secs, rva):
    for va, pr, sz in secs:
        if va <= rva < va + sz: return pr + (rva - va)
    return None

def pdata_bounds(path):
    data = open(path, "rb").read()
    nt = struct.unpack_from("<I", data, 0x3C)[0]
    n = struct.unpack_from("<H", data, nt+6)[0]; osz = struct.unpack_from("<H", data, nt+0x14)[0]
    so = nt+0x18+osz
    for i in range(n):
        s = so + i*0x28
        name = data[s:s+8].rstrip(b"\x00").decode("ascii","replace")
        va, vs, rs, rp = struct.unpack_from("<IIII", data, s+8)
        if name == ".pdata":
            ent = [struct.unpack_from("<III", data, off) for off in range(rp, rp+rs, 12)]
            return sorted((b, e) for b, e, u in ent)
    return []

class GA:
    def __init__(self, path):
        self.data, self.secs = load(path)
        self.ent = pdata_bounds(path)
        self.begins = [b for b, e in self.ent]
    def bytes_at(self, rva, n):
        o = rva2off(self.secs, rva)
        if o is None: return None
        return self.data[o:o+n]
    def func_len(self, rva):
        i = bisect.bisect_right(self.begins, rva) - 1
        if i < 0: return None
        b, e = self.ent[i]
        return e - b if b <= rva < e else None

def heuristic_mask(code, rva):
    """反汇编 code（自 rva 起），返回掩码 list[int|None]。
    通配模型（由 5 钩已知 diff 掩码反推）：
      - RIP 相对 disp32 全通配（镜像布局逐构建位移）
      - 元数据 token 型 imm32（0x01______~0x7F______ 高位字节>=0x01 且 >=0x100000）全通配
      - 小 imm32（栈大小/字段常量混淆）：仅通配最低字节（? 01 00 00 模式）
      - disp8/disp32 SIB 字段偏移：保留（跨构建稳定，V 已证）
      - 截断到最后一条完整指令（尾部半指令字节必变）"""
    from capstone.x86 import X86_REG_RIP
    md = Cs(CS_ARCH_X86, CS_MODE_64)
    md.detail = True
    mask = [b for b in code]
    end = 0
    for ins in md.disasm(code, rva):
        if ins.address + ins.size > rva + len(code): break
        end = ins.address - rva + ins.size
        # 1) RIP 相对：通配末尾 disp32
        for op in ins.operands:
            if op.type == 3 and op.mem.base == X86_REG_RIP and op.mem.index == 0:  # CS_OP_MEM
                off = ins.address - rva + ins.size - 4
                if 0 <= off and off + 4 <= len(mask):
                    for k in range(4): mask[off+k] = None
                break
        # 2) imm32 分类通配
        for op in ins.operands:
            if op.type == 2:  # CS_OP_IMM
                v = op.imm & 0xFFFFFFFF
                vb = struct.pack("<I", v)
                base = ins.address - rva
                idx = code.find(vb, base, base + ins.size)
                if idx < 0: continue
                if v >= 0x100000 and (v >> 24) != 0:
                    # 元数据 token / 大常量：整 4 字节轮换
                    for k in range(4): mask[idx+k] = None
                elif 0 < v < 0x100000:
                    # 混淆小常数：仅最低字节轮换
                    mask[idx] = None
    mask[end:] = [None]*(len(mask)-end)  # 截断半指令
    while mask and mask[-1] is None: mask.pop()
    return mask

_pat_cache = {}
def scan(ga, mask):
    key = tuple(mask)
    pat = _pat_cache.get(key)
    if pat is None:
        pat = re.compile(b"".join(b"." if m is None else re.escape(bytes([m])) for m in mask), re.DOTALL)
        _pat_cache[key] = pat
    hits = []
    for va, pr, sz in ga.secs:
        blob = ga.data[pr:pr+sz]
        for m in pat.finditer(blob): hits.append(va + m.start())
    return hits

def gen_sig(ga_old, rva, ga_targets, lens=(16,24,32,48,64,96,128,192,256)):
    """对老版 rva 生成启发式掩码签名；要求老版唯一，且在 ga_targets 各版上评估命中。
    返回 (mask_str, per_target_hits) 或 None。"""
    flen = ga_old.func_len(rva)
    if flen is None: return None
    for N in lens:
        N = min(N, flen)
        code = ga_old.bytes_at(rva, N)
        if code is None or len(code) < N: return None
        mask = heuristic_mask(code, rva)
        # 有效字节太少（全是通配）则加长
        if sum(1 for b in mask if b is not None) < 8:
            if N == flen: return None
            continue
        ho = scan(ga_old, mask)
        if len(ho) != 1 or ho[0] != rva:
            if N == flen: return None
            continue
        res = []
        allu = True
        for tag, ga2, truth_rva in ga_targets:
            h = scan(ga2, mask)
            ok = (len(h) == 1 and h[0] == truth_rva) if truth_rva else (len(h) == 1)
            res.append((tag, len(h), h[0] if len(h)==1 else None, ok))
            if not ok: allu = False
        ms = " ".join("?" if b is None else f"{b:02X}" for b in mask)
        return (ms, N, res, allu)
    return None

def main():
    old = GA(OLD); b2 = GA(B2); b3 = GA(B3)

    # ---- 阶段 1：5 钩校验启发式掩码法 ----
    print("=== stage1: validate heuristic mask on 5 hooks (known old/b2/b3) ===")
    tg = [("b2", b2, None), ("b3", b3, None)]
    good = 0
    for k, (ro, r2, r3) in HOOK.items():
        r = gen_sig(old, ro, [("b2", b2, r2), ("b3", b3, r3)])
        if not r:
            print(f"  {k}: GEN-FAIL"); continue
        ms, N, res, allu = r
        print(f"  {k}: len={N} " + " ".join(f"{t}:{'UNIQ-OK' if ok else str(h)}" for t,h,_,ok in res) + (" PASS" if allu else " FAIL"))
        good += allu
    print(f"stage1: {good}/5 pass")

    # ---- 阶段 2：推广到 47 RESOLVED ----
    print("\n=== stage2: generate for 47 RESOLVED method-entry targets ===")
    idrows = [l.split("\t") for l in open(IDENT, encoding="utf-8").read().splitlines()[1:]]
    resolved = [(int(r[0],16), r[5]) for r in idrows if len(r)>=6 and r[1]=="RESOLVED"]
    migrows = [l.split("\t") for l in open(MIG, encoding="utf-8").read().splitlines()[1:]]
    truth2 = {int(r[0],16): int(r[1],16) for r in migrows if len(r)>=2 and r[1].strip().startswith("0x")}
    for k,(ro,r2,r3) in HOOK.items(): truth2[ro] = r2

    out = open(OUT, "w", encoding="utf-8")
    out.write("old_rva\tparams\tmask\tb2_hits\tb2_rva\tb3_hits\tb3_rva\tstatus\n")
    cat = collections.Counter()
    for ro, params in resolved:
        known = truth2.get(ro)
        r = gen_sig(old, ro, [("b2", b2, known), ("b3", b3, None)])
        if not r:
            cat["GEN-FAIL"] += 1
            out.write(f"{ro:#x}\t{params}\t\t\t\t\t\tGEN-FAIL\n"); continue
        ms, N, res, allu = r
        b2h = next((x for x in res if x[0]=="b2")); b3h = next((x for x in res if x[0]=="b3"))
        st = "OK" if allu else ("B2-OK-B3-" + ("AMBIG" if b3h[1]>1 else "MISS"))
        cat[st] += 1
        out.write(f"{ro:#x}\t{params}\t{ms}\t{b2h[1]}\t{b2h[2] and hex(b2h[2]) or ''}\t{b3h[1]}\t{b3h[2] and hex(b3h[2]) or ''}\t{st}\n")
    out.close()
    print("categories:", dict(cat))
    print(f"output: {OUT}")

if __name__ == "__main__":
    main()
