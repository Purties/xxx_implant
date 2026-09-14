# named_objects.py - 提取转储中全部命名对象（IPC 契约面）
import re
d = open(r"c:\workspace\9-4#2\xxx\analysis\memscan\region_0_0x269C000.bin", "rb").read()
hits = set()
for m in re.finditer(rb"(?:[\x20-\x7e]\x00){6,}", d):
    hits.add(m.group().decode("utf-16-le"))
for m in re.finditer(rb"[\x20-\x7e]{6,}", d):
    hits.add(m.group().decode("ascii"))
objs = sorted(s for s in hits if s.startswith(("Local\\", "Global\\", "Session\\")))
print(f"{len(objs)} named objects")
for s in objs:
    print(" ", s)
