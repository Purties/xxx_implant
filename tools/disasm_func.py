# disasm_func.py - disassemble old/new GA at given RVA for skeleton design
import sys
import struct
from capstone import Cs, CS_ARCH_X86, CS_MODE_64

FILES = {
    "old": r"d:\9-4#2\tools\GameAssembly_old_0902.dll",
    "new": r"C:\冒险岛online\mxdclassic\GameAssembly.dll",
}

def sections_of(data):
    pe_off = struct.unpack_from("<I", data, 0x3C)[0]
    num_sec = struct.unpack_from("<H", data, pe_off + 6)[0]
    opt_size = struct.unpack_from("<H", data, pe_off + 0x14)[0]
    sec_off = pe_off + 0x18 + opt_size
    secs = []
    for i in range(num_sec):
        s = sec_off + i * 0x28
        name = data[s:s+8].rstrip(b"\x00").decode("ascii", "replace")
        vsize, vaddr, rawsize, rawptr = struct.unpack_from("<IIII", data, s + 8)
        secs.append((name, vaddr, vsize, rawptr, rawsize))
    return secs

def va_to_raw(secs, va):
    for name, vaddr, vsize, rawptr, rawsize in secs:
        if vaddr <= va < vaddr + max(vsize, rawsize):
            return rawptr + (va - vaddr)
    return None

def main():
    which = sys.argv[1]
    rva = int(sys.argv[2], 16)
    count = int(sys.argv[3]) if len(sys.argv) > 3 else 40
    data = open(FILES[which], "rb").read()
    secs = sections_of(data)
    raw = va_to_raw(secs, rva)
    if raw is None:
        print("unmapped")
        return
    md = Cs(CS_ARCH_X86, CS_MODE_64)
    code = data[raw:raw + count * 8]
    for ins in md.disasm(code, rva):
        b = code[ins.address - rva: ins.address - rva + ins.size]
        print(f"+{ins.address - rva:#05x} {ins.address:#x}: {ins.mnemonic:8s} {ins.op_str:<42s} ; {' '.join(f'{x:02x}' for x in b)}")
        if ins.address - rva > count * 8:
            break

if __name__ == "__main__":
    main()
