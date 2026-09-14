# rva_migrate4.py - improved matcher:
#  - section-constrained (old il2cpp -> new il2cpp only)
#  - mask: rel32/rel8 branches, rip-rel disp32, movabs imm64, AND imm32/16 with value >= 0x1000
#  - multi-anchor proximity: split into unmasked runs >=6; require all runs at exact relative offsets
#    (exact-offset multi-run is same as full masked compare; kept for clarity)
#  - escalate pattern length; require unique
import struct, json
from capstone import Cs, CS_ARCH_X86, CS_MODE_64

DUMP = r"d:\9-4#2\xxx\analysis\memscan\region_0_0x269C000.bin"
OLD  = r"d:\9-4#2\tools\GameAssembly_old_0902.dll"
NEW  = r"C:\冒险岛online\mxdclassic\GameAssembly.dll"
OUT  = r"d:\9-4#2\xxx\analysis\rva_migration.tsv"

dump = open(DUMP, "rb").read()
old  = open(OLD, "rb").read()
new  = open(NEW, "rb").read()

md = Cs(CS_ARCH_X86, CS_MODE_64)
md.detail = True
md.skipdata = True

OLD_IL2CPP = (0x487000, 0x485800, 0x4e3c600)   # va, raw, size
NEW_IL2CPP = (0x489000, 0x488400, 0x4efb600)

def old_va2raw(va):
    # old sections
    secs = [(0x1000, 0x400, 0x485400), (0x487000, 0x485800, 0x4e3c600),
            (0x52c4000, 0x52c1e00, 0x1539000), (0x67fd000, 0x67fae00, 0x3c1000)]
    for v, r, s in secs:
        if v <= va < v + s:
            return r + (va - v)
    return None

NEW_RAW0, NEW_RAW1 = NEW_IL2CPP[1], NEW_IL2CPP[1] + NEW_IL2CPP[2]
NEW_VA0 = NEW_IL2CPP[0]
newcode = new  # search within raw window

# ---------- collect RVAs (same as v3) ----------
CODE_LO, CODE_HI = 0x100000, 0x140000
STR_LO, STR_HI = 0x100000, 0x200000

def read_cstr(off):
    end = dump.find(b"\x00", off)
    if end < 0 or end - off > 120 or end == off:
        return None
    s = dump[off:end]
    return s.decode() if all(32 <= b < 127 for b in s) else None

insns = list(md.disasm(dump[CODE_LO:CODE_HI], CODE_LO))
hooks = []
labels = []
from capstone.x86 import X86_OP_MEM, X86_REG_RIP
for ins in insns:
    if ins.id == 0 or ins.mnemonic != "lea" or len(ins.operands) != 2 or ins.operands[1].type != X86_OP_MEM:
        continue
    mem = ins.operands[1].mem
    if mem.base == X86_REG_RIP:
        tgt = ins.address + ins.size + mem.disp
        if STR_LO <= tgt < STR_HI:
            s = read_cstr(tgt)
            if s:
                labels.append((ins.address, s))
    elif 0x10000 <= mem.disp < 0x4000000:
        hooks.append((ins.address, mem.disp))

def hint(addr):
    best = None
    for la, s in labels:
        d = la - addr
        if -0x30 <= d <= 0x100 and (best is None or abs(d) < abs(best[0] - addr)):
            best = (la, s)
    return best[1] if best else ""

rva_map = {}
for ha, rva in hooks:
    rva_map.setdefault(rva, hint(ha))
extras = {
    0x78EB60: "NpcDialog.Next (log string)",
    0x78EF10: "UIUtilDialogEx confirm (log string)",
    0xbbf663: "crash point",
}
for r, s in extras.items():
    rva_map.setdefault(r, s)
rvas = sorted(rva_map)
print(f"RVAs: {len(rvas)}")

# ---------- pattern builder with imm masking ----------
def build_pattern(raw, plen):
    code = old[raw:raw+plen]
    mask = bytearray([1]*len(code))
    for ins in md.disasm(code, 0):
        if ins.id == 0:
            continue
        istart = ins.address
        b = ins.bytes
        i = 0
        while i < len(b) and (b[i] in (0x66,0x67,0xF2,0xF3,0xF0,0x2E,0x3E,0x26,0x64,0x65) or 0x40 <= b[i] <= 0x4F):
            i += 1
        if i >= len(b):
            continue
        op = b[i]
        if op in (0xE8, 0xE9) and i+5 <= len(b):
            mask[istart+i+1:istart+i+5] = b"\x00"*4
        elif op == 0xEB and i+2 <= len(b):
            mask[istart+i+1] = 0
        elif 0x70 <= op <= 0x7F and i+2 <= len(b):
            mask[istart+i+1] = 0
        elif op == 0x0F and i+1 < len(b) and 0x80 <= b[i+1] <= 0x8F and i+6 <= len(b):
            mask[istart+i+2:istart+i+6] = b"\x00"*4
        # rip-relative modrm
        for j in range(i+1, min(i+6, len(b)-4)):
            modrm = b[j]
            mod, rm = (modrm >> 6) & 3, modrm & 7
            if mod == 0 and rm == 5:
                mask[istart+j+1:istart+j+5] = b"\x00"*4
                break
            if mod == 0 and rm == 4 and j+1 < len(b) and (b[j+1] & 7) == 5:
                mask[istart+j+2:istart+j+6] = b"\x00"*4
                break
        # movabs imm64
        if (b[0] & 0xF8) == 0x48 and 0xB8 <= op <= 0xBF:
            mask[istart+i+1:istart+i+9] = b"\x00"*8
        # generic imm32/imm16 masking when value large (>=0x1000): last 4 bytes of insn
        elif ins.size >= 5:
            tail4 = struct.unpack_from("<I", b, len(b)-4)[0]
            if tail4 >= 0x1000:
                # crude: mask last 4 bytes if not a branch target we already masked
                mask[istart+ins.size-4:istart+ins.size] = b"\x00"*4
    return bytes(code), bytes(mask)

def runs_of(pat, msk, minlen=6):
    runs = []
    i = 0
    while i < len(pat):
        if msk[i]:
            j = i
            while j < len(pat) and msk[j]:
                j += 1
            if j - i >= minlen:
                runs.append((i, pat[i:j]))
            i = j
        else:
            i += 1
    return runs

def match_new(pat, msk):
    runs = runs_of(pat, msk)
    if not runs:
        return -2, []
    aoff, anchor = max(runs, key=lambda r: len(r[1]))
    cands = []
    s = NEW_RAW0
    while True:
        idx = new.find(anchor, s, NEW_RAW1)
        if idx < 0:
            break
        base = idx - aoff
        if NEW_RAW0 <= base and base + len(pat) <= NEW_RAW1:
            ok = True
            for roff, run in runs:
                if new[base+roff:base+roff+len(run)] != run:
                    ok = False
                    break
            if ok:
                cands.append(NEW_VA0 + (base - NEW_RAW0))
        s = idx + 1
    if len(cands) == 1:
        return 1, cands
    return (2 if cands else 0), cands

results = []
for rva in rvas:
    raw = old_va2raw(rva)
    if raw is None:
        results.append((rva, rva_map[rva], None, "unmapped"))
        continue
    found, note = None, ""
    for plen in (128, 96, 64, 48, 32):
        pat, msk = build_pattern(raw, plen)
        st, cands = match_new(pat, msk)
        if st == 1:
            found, note = cands[0], f"unique@{plen}"
            break
        elif st == 2 and plen < 128:
            continue
        elif st == 2:
            note = f"multi({len(cands)})@{plen}"
        else:
            note = f"nomatch@{plen}"
    results.append((rva, rva_map[rva], found, note))

ok = 0
for rva, lbl, fr, note in results:
    ok += fr is not None
    print(f"  old {rva:#010x} -> new {hex(fr) if fr else '??????':>10}  [{note}]  {lbl}")
with open(OUT, "w") as f:
    f.write("old_rva\tnew_rva\tstatus\tlabel\n")
    for rva, lbl, fr, note in results:
        f.write(f"{rva:#x}\t{fr and hex(fr) or ''}\t{note}\t{lbl}\n")
print(f"\nmigrated {ok}/{len(results)} -> {OUT}")
