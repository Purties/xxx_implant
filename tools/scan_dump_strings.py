# scan_dump_strings.py - extract & grep strings from injected DLL memory dump
import re, sys

DUMP = r"d:\9-4#2\xxx\analysis\memscan\region_0_0x269C000.bin"
OUT  = r"d:\9-4#2\xxx\analysis\dump_strings_hits.txt"

data = open(DUMP, "rb").read()
print(f"dump size: {len(data):#x}", file=sys.stderr)

# ASCII strings >= 5
pat_ascii = re.compile(rb"[\x20-\x7e]{5,}")
strings = []  # (offset, text)
for m in pat_ascii.finditer(data):
    strings.append((m.start(), m.group().decode("ascii", "replace")))

KEYS = [
    "typedef", "dump11", "dump", "GameAssembly", "prologue", "ordinal",
    "SetVelocity", "DoCombatStep", "SetDamaged", "SetImpactNext",
    "version", "sha256", "SHA-256", "rva", "RVA", "method",
    "lease", "redeem", "skill-manager", "metadata", "hook",
    "11BE640", "11be640", "102E640", "102e640", "1660650", "1049B70",
    "ba7b80fc", "f381d853", "cdeaa78e", "a6636c74", "e1f1fe26", "fa00269a",
]

out = []
out.append(f"total strings: {len(strings)}\n")
for key in KEYS:
    hits = [(off, s) for off, s in strings if key in s]
    out.append(f"\n### key={key!r}  hits={len(hits)}")
    for off, s in hits[:60]:
        out.append(f"  @{off:#08x}  {s[:200]}")

open(OUT, "w", encoding="utf-8").write("\n".join(out))
print(f"written: {OUT}", file=sys.stderr)
