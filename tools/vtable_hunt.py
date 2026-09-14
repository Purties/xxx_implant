# vtable_hunt.py - locate version table rows and SHA-256 hashes in the injected DLL dump
import struct

DUMP = r"d:\9-4#2\xxx\analysis\memscan\region_0_0x269C000.bin"
data = open(DUMP, "rb").read()
print(f"dump size {len(data):#x}")

HASHES = ["f381d853", "cdeaa78e", "a6636c74", "e1f1fe26", "fa00269a"]

# 1) as ascii hex strings
for h in HASHES:
    s = h.encode()
    i = data.find(s)
    print(f"ascii {h}: {'@'+hex(i) if i>=0 else 'not found'}")
    if i >= 0:
        # show surrounding
        lo = max(0, i - 0x40)
        print("   ctx:", data[lo:i+0x60].hex(' '))

# 2) as binary (first 4 bytes of each hash)
print()
for h in HASHES:
    b = bytes.fromhex(h)
    i = data.find(b)
    print(f"bin {h}…: {'@'+hex(i) if i>=0 else 'not found'}")

# 3) find "GameAssembly.dll" string
for pat in (b"GameAssembly.dll", b"GameAssembly.dll\x00"):
    s = 0
    while True:
        i = data.find(pat, s)
        if i < 0:
            break
        print(f"'{pat[:16]}' @{i:#x}")
        s = i + 1
