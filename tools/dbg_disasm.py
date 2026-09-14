# dbg_disasm.py
from capstone import Cs, CS_ARCH_X86, CS_MODE_64
from capstone.x86 import X86_OP_MEM, X86_REG_RIP
dump = open(r"d:\9-4#2\xxx\analysis\memscan\region_0_0x269C000.bin", "rb").read()
print("dump size", hex(len(dump)))
md = Cs(CS_ARCH_X86, CS_MODE_64)
md.detail = True
code = dump[0x127c00:0x127d00]
n = 0
for ins in md.disasm(code, 0x127c00):
    n += 1
    if ins.mnemonic in ("lea", "mov"):
        ops = [(o.type, getattr(o, "reg", None)) for o in ins.operands]
        mems = [(o.mem.base, o.mem.disp) for o in ins.operands if o.type == X86_OP_MEM]
        print(hex(ins.address), ins.mnemonic, ins.op_str, "|", ops, mems)
print("total insns:", n)
