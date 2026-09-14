# slot_offsets.py - for each dispatch lea site, find the following `mov [rip+disp], rax` slot image-offset
import struct
from capstone import Cs, CS_ARCH_X86, CS_MODE_64

DUMP = r"d:\9-4#2\xxx\analysis\memscan\region_0_0x269C000.bin"
data = open(DUMP, "rb").read()
BASE = 0x80000000
md = Cs(CS_ARCH_X86, CS_MODE_64)
md.detail = True

SITES = [
    ("SetImpactNext", 0x127CDB),
    ("SetVelocity",   0x127D07),
    ("DoCombatStep",  0x127D33),
    ("InputUpdate",   0x127DD5),
    ("SetDamaged",    0x12800A),
]
print(f"{'hook':14s} {'lea_off':>10s} {'slot_mov_off':>12s} {'slot_img_off':>13s}")
for name, off in SITES:
    # disasm a few instructions from the lea
    slot_off = None
    for ins in md.disasm(data[off:off + 0x30], BASE + off):
        if ins.mnemonic == "mov" and "[rip" in ins.op_str and "rax" in ins.op_str:
            # slot write: mov qword ptr [rip + disp], rax
            disp = ins.operands[0].mem.disp
            slot_va = ins.address + ins.size + disp
            slot_off = slot_va - BASE
            slot_mov_off = ins.address - BASE
            break
    print(f"{name:14s} {off:#010x} {slot_mov_off:#014x} {slot_off:#014x}")
