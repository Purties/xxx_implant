# extract_dispatch.py - extract all lea [reg+disp32] GameAssembly RVAs from dispatch code,
# and dump version-row records
import re
from capstone import Cs, CS_ARCH_X86, CS_MODE_64

DUMP = r"d:\9-4#2\xxx\analysis\memscan\region_0_0x269C000.bin"
data = open(DUMP, "rb").read()
BASE = 0x80000000  # inferred manual-map preferred base

out = []

# --- 1. disassemble dispatch area, collect lea disp32 ---
md = Cs(CS_ARCH_X86, CS_MODE_64)
start, end = 0x127000, 0x128400
code = data[start:end]
out.append("===== dispatch code lea targets (0x127000-0x128400) =====")
for insn in md.disasm(code, BASE + start):
    if insn.mnemonic == "lea" and ("rcx" in insn.op_str or "rbx" in insn.op_str) or \
       insn.mnemonic == "lea" and "+ 0x" in insn.op_str:
        m = re.search(r"\[(r\w+) \+ (0x[0-9a-f]+)\]", insn.op_str)
        if m:
            disp = int(m.group(2), 16)
            out.append(f"@{insn.address - BASE:#08x}  {insn.mnemonic} {insn.op_str:<28} -> GameAssembly+{disp:#x}")
    elif insn.mnemonic in ("cmp", "jnz", "jz", "mov", "xor", "test"):
        out.append(f"@{insn.address - BASE:#08x}  {insn.mnemonic} {insn.op_str}")

# --- 2. version row records at 0x185780 (+0x40 x5) ---
out.append("")
out.append("===== version row records @0x185780 (5 x 0x40) =====")
for i in range(5):
    off = 0x185780 + i * 0x40
    chunk = data[off:off+0x40]
    hexpart = " ".join(f"{b:02x}" for b in chunk)
    asc = "".join(chr(b) if 0x20 <= b < 0x7f else "." for b in chunk)
    out.append(f"row{i} @{off:#08x}: {hexpart}")
    out.append(f"           {asc}")
    # interpret as 8 qwords
    qs = [int.from_bytes(chunk[j*8:j*8+8], "little") for j in range(8)]
    out.append("  qwords: " + " ".join(f"{q:#x}" for q in qs))

open(r"d:\9-4#2\xxx\analysis\dispatch_extract.txt", "w", encoding="utf-8").write("\n".join(out) + "\n")
print("written")
