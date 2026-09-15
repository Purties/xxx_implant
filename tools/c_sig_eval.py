# c_sig_eval.py - 评估 C(DoCombatStep) 松掩码 + 结构约束 在三构建的收敛性
import pefile, re, bisect

BUILDS = {
    'b1': (r'c:\workspace\9-4#2\tools\GameAssembly_old_0902.dll', 0x11BEF10, 0x11BE670),
    'b2': (r'c:\workspace\9-4#2\tools\GameAssembly.dll',           0x1215270, 0x1214940),
    'b3': (r'D:\build3_backup\GameAssembly_build3.dll',            0x1218010, 0x1217760),
}
# 松掩码：只保留跨构建稳定的骨架（sub rsp,imm / lea rip / mov [rsp+disp],rax），
# 帧大小、栈槽偏移、disp 全掩码
LOOSE = "48 83 EC ? 48 8D 05 ? 00 00 00 48 89 44 24"
mask = [None if t == '?' else int(t, 16) for t in LOOSE.split()]
pat = re.compile(b''.join(b'.' if b is None else re.escape(bytes([b])) for b in mask), re.DOTALL)

def il2cpp(pe):
    for s in pe.sections:
        if s.Name.rstrip(b'\x00') == b'il2cpp':
            return s.VirtualAddress, s.PointerToRawData, s.SizeOfRawData
    return None

def funcs(pe):
    pe.parse_data_directories(directories=[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_EXCEPTION']])
    return sorted((e.struct.BeginAddress, e.struct.EndAddress) for e in pe.DIRECTORY_ENTRY_EXCEPTION)

for tag, (p, Ctrue, Itrue) in BUILDS.items():
    pe = pefile.PE(p, fast_load=True); d = pe.__data__
    va, pr, sz = il2cpp(pe); blob = d[pr:pr+sz]
    hits = [va + m.start() for m in pat.finditer(blob)]
    F = funcs(pe); begins = [f[0] for f in F]
    def func_of(r):
        i = bisect.bisect_right(begins, r) - 1
        return F[i] if i >= 0 and F[i][0] <= r < F[i][1] else None
    def calls_I(r):
        fe = func_of(r)
        if not fe: return False
        b, e = fe; off = pr + (r - va); sub = d[off:off + (e - b)]
        for m in re.finditer(b'\xe8', sub):
            o = m.start()
            if o + 5 > len(sub): continue
            rel = int.from_bytes(sub[o+1:o+5], 'little', signed=True)
            if r + o + 5 + rel == Itrue: return True
        return False
    small = [h for h in hits if (lambda fe: fe and fe[1]-fe[0] < 300)(func_of(h))]
    final = [h for h in small if calls_I(h)]
    print(f"{tag}: loose={len(hits)} small={len(small)} small+callI={len(final)} "
          f"trueC({Ctrue:#x})-in={Ctrue in final} {[hex(x) for x in final[:6]]}")
