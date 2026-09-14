# verify_new_ga.py - 新版 GA 离线验证：导出表 + 5 新 RVA 函数入口 + 序言结构
import pefile, sys

NEW = r"c:\workspace\9-4#2\tools\GameAssembly.dll"
OLD = r"c:\workspace\9-4#2\tools\GameAssembly_old_0902.dll"

pe = pefile.PE(NEW, fast_load=True)
pe.parse_data_directories(directories=[
    pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_EXPORT"],
    pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_EXCEPTION"],
])
exps = [e.name.decode() for e in pe.DIRECTORY_ENTRY_EXPORT.symbols if e.name]
il = sorted(n for n in exps if n.startswith("il2cpp"))
print(f"exports={len(exps)} il2cpp={len(il)}")
KEY = ["il2cpp_domain_get","il2cpp_domain_get_assemblies","il2cpp_assembly_get_image",
       "il2cpp_image_get_class","il2cpp_image_get_class_count","il2cpp_class_get_name",
       "il2cpp_class_get_namespace","il2cpp_class_get_methods","il2cpp_method_get_name",
       "il2cpp_method_get_param_count","il2cpp_image_get_name"]
print("key APIs:", all(k in exps for k in KEY))

funcs = sorted((e.struct.BeginAddress, e.struct.EndAddress) for e in pe.DIRECTORY_ENTRY_EXCEPTION)
begins = {b for b, _ in funcs}
def func_at(rva):
    for b, e in funcs:
        if b == rva: return e - b
    return None

# 5 新 RVA（§5.7.1）
NEW_RVAS = {"V":0x12144F0, "I":0x1214940, "C":0x1215270, "D":0x10D74B0, "U":0x14DB0B0}
OLD_RVAS = {"V":0x11BE640, "I":0x11BE670, "C":0x11BEF10, "D":0x1049B70, "U":0x1660650}

po = pefile.PE(OLD, fast_load=True)
po.parse_data_directories(directories=[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_EXCEPTION"]])
oldf = {e.struct.BeginAddress: e.struct.EndAddress - e.struct.BeginAddress for e in po.DIRECTORY_ENTRY_EXCEPTION}

def read(pe_, rva, n):
    for s in pe_.sections:
        if s.VirtualAddress <= rva < s.VirtualAddress + s.Misc_VirtualSize:
            off = s.PointerToRawData + (rva - s.VirtualAddress)
            return pe_.__data__[off:off+n]
    return b""

print("\ntag  new_rva  new@pdata(size)  old@pdata(size)  new_prologue")
for t in "VICDU":
    r = NEW_RVAS[t]
    sz = func_at(r)
    osz = oldf.get(OLD_RVAS[t])
    b = read(pe, r, 16).hex(" ")
    print(f"{t}  {r:#x}  {sz if sz else 'NOT-FUNC-ENTRY'}({sz or ''})  old={osz}  {b}")
