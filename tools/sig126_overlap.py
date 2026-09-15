# sig126_overlap.py - 47 RESOLVED 目标里，有多少具备 (old,b2) 真值对可用于 diff 生成
import sys, os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import sig126_gen as G

idrows=[l.split("\t") for l in open(G.IDENT,encoding="utf-8").read().splitlines()[1:]]
resolved={int(r[0],16):r[5] for r in idrows if len(r)>=6 and r[1]=="RESOLVED"}
migrows=[l.split("\t") for l in open(G.MIG,encoding="utf-8").read().splitlines()[1:]]
mig={int(r[0],16):int(r[1],16) for r in migrows if len(r)>=2 and r[1].strip().startswith("0x")}
HOOK_OLD={ro for ro,_,_ in G.HOOK.values()}

paired=[ro for ro in resolved if ro in mig]
hooked=[ro for ro in resolved if ro in HOOK_OLD]
unpaired=[ro for ro in resolved if ro not in mig and ro not in HOOK_OLD]
print(f"RESOLVED total: {len(resolved)}")
print(f"  with (old,b2) diff pair via rva_migration: {len(paired)}")
print(f"  are the 5 hooks (also have pair): {len(hooked)}")
print(f"  NO pair (only old bytes): {len(unpaired)}")
print("  unpaired old RVAs:", ", ".join(f"{r:#x}" for r in sorted(unpaired)))
# also: mig pairs that are NOT method entries
mig_notentry=[ro for ro in mig if ro not in resolved]
print(f"rva_migration pairs that are NOT_METHOD_ENTRY (mid-function): {len(mig_notentry)}")
