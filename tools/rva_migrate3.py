# rva_migrate3.py - full pipeline:
#   1) collect hook RVAs from dispatch code (+ nearest label as hint)
#   2) masked-pattern match old GA -> new GA
#   3) output TSV mapping
import struct, json
from capstone import Cs, CS_ARCH_X86, CS_MODE_64
from capstone.x86 import X86_OP_MEM, X86_REG_RIP

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

# ---------- old/new GA section maps ----------
def sections(path):
    d = open(path, "rb").read()
    pe = struct.unpack_from("<I", d, 0x3C)[0]
    n = struct.unpack_from("<H", d, pe+6)[0]
    osz = struct.unpack_from("<H", d, pe+0x14)[0]
    so = pe + 0x18 + osz
    out = []
    for i in range(n):
        s = so + i*0x28
        nm = d[s:s+8].rstrip(b"\x00").decode("ascii","replace")
        vs, va, rs, rp = struct.unpack_from("<IIII", d, s+8)
        out.append((nm, va, vs, rp, rs))
    return out

old_sec = sections(OLD)
new_sec = sections(NEW)

def va2raw(sec, va):
    for nm, vaddr, vs, rp, rs in sec:
        if vaddr <= va < vaddr + max(vs, rs):
            return rp + (va - vaddr)
    return None

# new GA code search range (raw): .text + il2cpp
NEW_CODE = []
for nm, va, vs, rp, rs in new_sec:
    if nm in (".text", "il2cpp"):
        NEW_CODE.append((rp, rs, va))
print("new code raw ranges:", [(hex(a),hex(b)) for a,b,_ in NEW_CODE])

# ---------- 1) collect hook RVAs + labels ----------
CODE_LO, CODE_HI = 0x100000, 0x140000
STR_LO, STR_HI = 0x100000, 0x200000

def read_cstr(off):
    end = dump.find(b"\x00", off)
    if end < 0 or end - off > 120 or end == off:
        return None
    s = dump[off:end]
    return s.decode() if all(32 <= b < 127 for b in s) else None

insns = list(md.disasm(dump[CODE_LO:CODE_HI], CODE_LO))
hooks = []   # (addr, rva)
labels = []  # (addr, string)
for ins in insns:
    if ins.mnemonic != "lea" or len(ins.operands) != 2 or ins.operands[1].type != X86_OP_MEM:
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

# nearest label within +0x100 as hint
def hint(addr):
    best = None
    for la, s in labels:
        d = la - addr
        if -0x30 <= d <= 0x100:
            if best is None or abs(d) < abs(best[0]-addr):
                best = (la, s)
    return best[1] if best else ""

rva_map = {}  # rva -> label hint
for ha, rva in hooks:
    rva_map.setdefault(rva, hint(ha))

# extra well-known RVAs (log strings / crash analysis)
extras = {
    0x78EB60: "NpcDialog.Next (log string)",
    0x78EF10: "UIUtilDialogEx confirm (log string)",
    0xbbf663: "crash point 0xbbf663",
    0x1049b70: "crash-site RVA 0x1049b70",
    0x1660650: "crash-site RVA 0x1660650",
}
for r, s in extras.items():
    rva_map.setdefault(r, s)

rvas = sorted(rva_map)
print(f"total RVAs to migrate: {len(rvas)}")

# ---------- 2) masked pattern builder ----------
def build_pattern(raw, plen):
    """returns (bytes, mask) mask:1=compare,0=wild ; disasm to find address-bearing fields"""
    code = old[raw:raw+plen]
    mask = bytearray([1]*len(code))
    pos = 0
    for ins in md.disasm(code, 0):
        if ins.id == 0:
            continue
        istart = ins.address
        ib = ins.bytes
        # byte-level scan inside insn for risky fields:
        b = ib
        i = 0
        # skip prefixes & rex
        while i < len(b) and (b[i] in (0x66,0x67,0xF2,0xF3,0xF0,0x2E,0x3E,0x26,0x3E,0x64,0x65) or 0x40 <= b[i] <= 0x4F):
            i += 1
        if i >= len(b):
            continue
        op = b[i]
        # E8/E9 rel32, EB rel8, 70-7F rel8, 0F8x rel32
        if op in (0xE8, 0xE9) and i+5 <= len(b):
            mask[istart+i+1:istart+i+5] = b"\x00"*4
        elif op == 0xEB and i+2 <= len(b):
            mask[istart+i+1] = 0
        elif 0x70 <= op <= 0x7F and i+2 <= len(b):
            mask[istart+i+1] = 0
        elif op == 0x0F and i+1 < len(b) and 0x80 <= b[i+1] <= 0x8F and i+6 <= len(b):
            mask[istart+i+2:istart+i+6] = b"\x00"*4
        # rip-relative modrm (mod=00 rm=101) or sib with base=101 mod=00
        for j in range(i+1, min(i+6, len(b)-4)):
            modrm = b[j]
            mod, rm = (modrm>>6)&3, modrm&7
            if mod == 0 and rm == 5:
                mask[istart+j+1:istart+j+5] = b"\x00"*4
                break
            if mod == 0 and rm == 4 and j+1 < len(b) and (b[j+1]&7) == 5:
                mask[istart+j+2:istart+j+6] = b"\x00"*4
                break
        # movabs REX.W B8+r : imm64 wild
        if (b[0] & 0xF0) == 0x40 and (b[0] & 8) and 0xB8 <= op <= 0xBF:
            mask[istart+i+1:istart+i+9] = b"\x00"*8
        pos = istart + ins.size
        if pos >= plen:
            break
    return bytes(code[:plen]), bytes(mask[:plen])

def match_new(pat, msk):
    # anchor = longest masked-in run >= 8
    best_run = (0, 0)
    cur = 0
    for i, m in enumerate(msk):
        if m:
            cur += 1
            if cur > best_run[1]:
                best_run = (i - cur + 1, cur)
        else:
            cur = 0
    aoff, alen = best_run
    if alen < 6:
        return -2, []
    anchor = pat[aoff:aoff+alen]
    cands = []
    for rp, rs, rva_base in NEW_CODE:
        s = rp
        end = rp + rs
        while True:
            idx = new.find(anchor, s, end)
            if idx < 0:
                break
            # verify full pattern
            base = idx - aoff
            if base >= rp and base + len(pat) <= end:
                ok = True
                for k in range(len(pat)):
                    if msk[k] and new[base+k] != pat[k]:
                        ok = False
                        break
                if ok:
                    cands.append(rva_base + (base - rp))
            s = idx + 1
    return (1 if len(cands) == 1 else (0 if not cands else 2)), cands

# ---------- 3) run migration ----------
results = []
for rva in rvas:
    raw = va2raw(old_sec, rva)
    if raw is None:
        results.append((rva, rva_map[rva], None, "unmapped-old"))
        continue
    found = None
    note = ""
    for plen in (64, 96, 128, 48, 32, 24, 16):
        pat, msk = build_pattern(raw, plen)
        st, cands = match_new(pat, msk)
        if st == 1:
            found = cands[0]
            note = f"unique@{plen}"
            break
        elif st == 2:
            # try longer for disambiguation
            if plen < 128:
                continue
            note = f"multi({len(cands)})@{plen}"
            break
        else:
            note = f"nomatch@{plen}"
            continue
    results.append((rva, rva_map[rva], found, note))
    print(f"  old {rva:#010x} -> new {hex(found) if found else '??????':>10}  [{note}]  {rva_map[rva]}")

with open(OUT, "w") as f:
    f.write("old_rva\tnew_rva\tstatus\tlabel\n")
    for rva, lbl, fr, note in results:
        f.write(f"{rva:#x}\t{fr and hex(fr) or ''}\t{note}\t{lbl}\n")
ok = sum(1 for _,_,fr,_ in results if fr)
print(f"\nmigrated {ok}/{len(results)} -> {OUT}")
