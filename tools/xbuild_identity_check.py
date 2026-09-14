# xbuild_identity_check.py - 跨构建身份键稳定性判别
# 老版（0902）现场捕获的 7 个身份哈希是否原样存在于新版（ba7b80fc）元数据串表
NEW = r"C:\workspace\9-4#2\tools\global-metadata_new.dat"
OLD = r"C:\冒险岛online\mxdclassic\Maplestory_Classic_Data\il2cpp_data\Metadata\global-metadata.dat"

keys = {
    "class V/I/C": "f46670bd6ea22817dec4b7ac9c5b7bccdc12d9bdca55d798ec278f4b77d917c",
    "class D":     "ac815ae99e729e8eaca2294e1428a4c8e8c039e628b5eedaf9ad76294699af7",
    "class U":     "b6be5581803c58bcb4bb4580ce0a21e36b506d742cc5f1c8564bd768f92ce0c",
    "method V":    "d4f1d9ba5f1bd5ee24bbe44d0916b19e4ac47142d72644eb413f409759c2fde",
    "method I":    "bcc2b2aa4d3e4bca953011745270a63118dd621f5cf6c8571e590152f5f219f",
    "method C":    "e174a2619425855250e3f20ebd706c11eb0b7b9abbdfa8e448768c2835313a0",
    "method D":    "d88bcb202e7f57be17f6306bbc1e0030dc947078cb4e023bb15be8e0fe7cd51",
}

dn = open(NEW, "rb").read()
do = open(OLD, "rb").read()
print(f"new metadata: {len(dn)} bytes, header={dn[:4]}")
print(f"old metadata: {len(do)} bytes, header={do[:4]}")

hit = 0
for k, v in keys.items():
    pos = dn.find(v.encode())
    if pos >= 0:
        hit += 1
        print(f"{k:14s} FOUND @ {pos:#x}")
    else:
        print(f"{k:14s} MISSING")
print(f"\nVERDICT: {hit}/7 identity keys present in NEW metadata")

# 控制组
fake = "0123456789abcdef" * 4
print("control fake-64hex present:", dn.find(fake.encode()) >= 0)
print("'Update' string present:", b"Update" in dn)

# 若轮换：统计老版串表中的 64hex 有多少在新版消失（抽样）
import re
if hit < 7:
    oldstr = set(re.findall(rb"[0-9a-f]{64}", do))
    newstr = set(re.findall(rb"[0-9a-f]{64}", dn))
    inter = len(oldstr & newstr)
    print(f"\n64hex strings: old={len(oldstr)} new={len(newstr)} intersection={inter}")
