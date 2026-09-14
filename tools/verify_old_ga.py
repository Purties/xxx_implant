# verify_old_ga.py - verify old GameAssembly backup: sections, and that hardcoded RVAs land on clean instruction boundaries
import struct
from capstone import Cs, CS_ARCH_X86, CS_MODE_64

OLD = r"d:\9-4#2\tools\GameAssembly_old_0902.dll"
data = open(OLD, "rb").read()
print(f"old GA size: {len(data):#x}")

# minimal PE parse
pe_off = struct.unpack_from("<I", data, 0x3C)[0]
num_sec = struct.unpack_from("<H", data, pe_off + 6)[0]
opt_size = struct.unpack_from("<H", data, pe_off + 0x14)[0]
opt = pe_off + 0x18
image_base = struct.unpack_from("<Q", data, opt + 0x18)[0]
sec_off = opt + opt_size
sections = []
for i in range(num_sec):
    s = sec_off + i * 0x28
    name = data[s:s+8].rstrip(b"\x00").decode("ascii", "replace")
    vsize, vaddr, rawsize, rawptr = struct.unpack_from("<IIII", data, s + 8)
    sections.append((name, vaddr, vsize, rawptr, rawsize))
    print(f"  {name:10s} VA={vaddr:#010x} VSize={vsize:#010x} Raw={rawptr:#010x} RawSize={rawsize:#010x}")
print(f"ImageBase: {image_base:#x}")

def va_to_raw(va):
    for name, vaddr, vsize, rawptr, rawsize in sections:
        if vaddr <= va < vaddr + max(vsize, rawsize):
            return rawptr + (va - vaddr)
    return None

# hardcoded RVAs from dispatch_extract.txt (in lea [rbx + rva] order)
rvas = [
    0x12cdb10, 0x5e4580, 0x5e7310, 0x5e94b0, 0xcf91c0, 0xc36270, 0x8316e0, 0xc6a600,
    0x11be670, 0x11be640, 0x11bef10, 0x11ccae0, 0x165e6e0, 0x165f840, 0x1660650,
    0xf66e20, 0xf6c590, 0xf6f4d0, 0xf6a910, 0xf73510, 0xf6aa40, 0xf73df0,
    0x1429640, 0x6e2af0, 0x6e2880, 0x6e2500, 0xf23d90, 0x1001fe0, 0x1049b70,
    0x10e7a00, 0x1cd88c0, 0x1cce780, 0xcfd0d0, 0xcfd1c0, 0xcfd1e0, 0xcfd0f0,
    0xcfd2d0, 0xcfd2b0, 0xcfd6b0, 0x7634a0, 0x763960, 0x763fc0, 0x765090,
    0x765860, 0x765a90, 0xb25d10, 0xc0d8a0, 0xc0d8c0, 0xc0d8f0, 0xc0d920,
    0xc0d950, 0xc0da40, 0xc0fc50, 0xc15570,
]

md = Cs(CS_ARCH_X86, CS_MODE_64)
md.skipdata = True

def insn_boundary_check(rva):
    """disasm backwards window, check an instruction starts exactly at rva"""
    raw = va_to_raw(rva)
    if raw is None:
        return None, "unmapped"
    start = max(0, raw - 32)
    ctx = data[start:raw + 16]
    base = image_base + (start - sections[0][3] + sections[0][1]) if False else 0
    # disasm from window start (address labels irrelevant)
    last_start = None
    for ins in md.disasm(ctx, 0):
        if ins.address == 32 - (raw - start):
            return True, ins.mnemonic + " " + ins.op_str
    return False, ""

print("\n=== RVA -> old GA instruction boundary check ===")
good = 0
for rva in rvas:
    raw = va_to_raw(rva)
    if raw is None:
        print(f"  {rva:#x}: UNMAPPED")
        continue
    # disasm a window ending just after rva; check instruction starts exactly at raw
    wstart = raw - 24
    ctx = data[wstart:raw + 8]
    hit = None
    for ins in md.disasm(ctx, 0):
        if ins.address == 24:
            hit = f"{ins.mnemonic} {ins.op_str}"
    ok = hit is not None
    good += ok
    print(f"  {rva:#x}: {'OK  ' if ok else 'MID-INSN'} {hit or ''}")
print(f"\nclean boundaries: {good}/{len(rvas)}")
