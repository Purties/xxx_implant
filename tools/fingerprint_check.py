# fingerprint_check.py - 静态指纹自检：开发机路径/源文件名/签名串残留
data = open(r"c:\workspace\9-4#2\implant\implant.dll", "rb").read()
bad = [b"workspace", b"implant.c", b"9-4#2", b"Administrator", b"sig126", b"mingw"]
print("size:", len(data))
for b in bad:
    n = data.count(b)
    print(f"  {b.decode():12s}: {n} {'<-- LEAK' if n else 'clean'}")
