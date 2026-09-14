# hexdump.py - hex dump a region of the injected DLL dump
import sys

DUMP = r"d:\9-4#2\xxx\analysis\memscan\region_0_0x269C000.bin"

def hexdump(path, start, length, out):
    data = open(path, "rb").read()
    lines = []
    end = min(start + length, len(data))
    for off in range(start, end, 16):
        chunk = data[off:off+16]
        hexpart = " ".join(f"{b:02x}" for b in chunk)
        asciipart = "".join(chr(b) if 0x20 <= b < 0x7f else "." for b in chunk)
        lines.append(f"@{off:#08x}  {hexpart:<47}  {asciipart}")
    open(out, "a", encoding="utf-8").write("\n".join(lines) + "\n")

out = sys.argv[1]
open(out, "w").write("")
for start, length, label in [
    (0x181a00, 0x400, "labels dump11 area"),
    (0x183f00, 0x300, "version table area"),
    (0x127C00, 0x500, "RVA table area (lea rax,[rbx+disp32])"),
]:
    with open(out, "a") as f:
        f.write(f"\n===== {label} @{start:#x} len={length:#x} =====\n")
    hexdump(DUMP, start, length, out)
print("written:", out)
