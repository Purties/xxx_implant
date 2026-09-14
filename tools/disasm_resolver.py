# disasm_resolver.py - disassemble resolver/logging functions around the two xref sites
from capstone import Cs, CS_ARCH_X86, CS_MODE_64

BIN = r"d:\9-4#2\xxx\analysis\memscan\region_0_0x269C000.bin"
BASE = 0x180000000
data = open(BIN, "rb").read()
md = Cs(CS_ARCH_X86, CS_MODE_64)
md.detail = True

def disasm(off, n, note=""):
    print(f"\n--- {note} @{off:#x} len={n:#x} ---")
    code = data[off:off+n]
    for ins in md.disasm(code, BASE + off):
        a = ins.address - BASE
        # annotate rip-relative targets
        ann = ""
        if ins.id != 0:
            for op in ins.operands:
                if op.type == 2 and op.mem.base == 41:
                    t = ins.address + ins.size + op.mem.disp - BASE
                    if 0 <= t < len(data):
                        # peek string
                        s = data[t:t+40].split(b"\x00")[0]
                        try:
                            txt = s.decode("ascii")
                            if all(32 <= c < 127 for c in s) and len(s) >= 4:
                                ann = f"  ; -> {t:#x} \"{txt[:38]}\""
                            else:
                                ann = f"  ; -> {t:#x}"
                        except Exception:
                            ann = f"  ; -> {t:#x}"
        print(f"  {a:#x}: {ins.mnemonic} {ins.op_str}{ann}")

disasm(0x121d80, 0x220, "xref site A (lbl_rva+metadata)")
disasm(0x122430, 0x220, "xref site B (lbl_typedef1514_m4)")
