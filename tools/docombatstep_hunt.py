# docombatstep_hunt.py - identify new DoCombatStep among callers of new big SetImpactNext (0x1214520)
# DoCombatStep traits (old): tiny func (~0xb3), starts directly with `sub rsp,imm8` (no pushes),
# obfuscated lea-chain prologue, dispatcher tail, call to big-I near end.
import struct
from capstone import Cs, CS_ARCH_X86, CS_MODE_64

NEW = r"C:\冒险岛online\mxdclassic\GameAssembly.dll"
data = open(NEW, "rb").read()
RAW0, RAW1, VA0 = 0x488400, 0x488400 + 0x4efb600, 0x489000

md = Cs(CS_ARCH_X86, CS_MODE_64)

CALLERS = [0xf30a37, 0xf310d1, 0xf33878, 0xf33ac7, 0xf5ac22, 0xf5ad20, 0xf62e61,
           0xf80b71, 0xf8528f, 0xf8f9a5, 0xfa76ea, 0xfe6c8e, 0x1001eca, 0x1032304,
           0x1078ab6, 0x1084f78, 0x108d8ef, 0x108d923, 0x108de0b, 0x108de42,
           0x108e188, 0x108e1b7, 0x1090052, 0x109041c, 0x1091375, 0x109937a,
           0x10993a2, 0x10c2e7d, 0x10f612b, 0x1103ea6, 0x1103ee1, 0x11f3787,
           0x11f68ae, 0x1209d8b]

def try_start(cand_va, site_va):
    """disasm forward from cand; return insn list up to site if reached cleanly, else None"""
    raw = RAW0 + (cand_va - VA0)
    insns = []
    for ins in md.disasm(data[raw:raw + (site_va - cand_va) + 8], cand_va):
        insns.append(ins)
        if ins.address == site_va:
            return insns
        if ins.address > site_va:
            return None
    return None

for site in CALLERS:
    site_raw = RAW0 + (site - VA0)
    # candidate starts: 0x10-aligned, within [site-0x140, site-0x10]
    for back in range(0x10, 0x150, 0x10):
        cand_raw = site_raw - back
        cand_va = site - back
        # must start with sub rsp, imm8 (48 83 ec) and NOT be preceded by more code mid-stream
        if data[cand_raw:cand_raw+3] != bytes.fromhex("48 83 ec"):
            continue
        insns = try_start(cand_va, site)
        if insns is None:
            continue
        # check traits
        txt = "\n".join(f"{i.mnemonic} {i.op_str}" for i in insns)
        has_lea_chain = txt.count("lea") >= 2 and "qword ptr [rip" in txt
        has_movzx_stub = "0f b6 50" in data[RAW0+cand_va-VA0:RAW0+site-VA0+0x40].hex(' ') or \
                         any("movzx" in t and "0x10" in t for t in txt.split("\n"))
        print(f"site {site:#x} <- start {cand_va:#x} (len {site-cand_va:#x})")
        for i in insns[:6]:
            print(f"    +{i.address-cand_va:#05x}: {i.mnemonic:8s} {i.op_str}")
        print(f"    ... lea_chain={has_lea_chain} movzx10={has_movzx_stub}")
