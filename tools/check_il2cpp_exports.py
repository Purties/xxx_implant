# check_il2cpp_exports.py - 阶段1预备：验证 GameAssembly.dll 的 il2cpp_* 导出 API
# 目的：确认运行时解析（按 typedef/方法动态取指针）所需的导出函数是否存在
import sys

try:
    import pefile
except ImportError:
    print("pefile not available", file=sys.stderr); sys.exit(1)

DLL = sys.argv[1] if len(sys.argv) > 1 else r"c:\workspace\9-4#2\tools\GameAssembly_old_0902.dll"
pe = pefile.PE(DLL, fast_load=True)
pe.parse_data_directories(directories=[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_EXPORT"]])

if not hasattr(pe, "DIRECTORY_ENTRY_EXPORT"):
    print("NO EXPORT TABLE"); sys.exit(0)

exps = pe.DIRECTORY_ENTRY_EXPORT.symbols
names = [e.name.decode() if e.name else f"ord{e.ordinal}" for e in exps]
print(f"total exports: {len(names)}")

il2cpp = sorted(n for n in names if n.lower().startswith("il2cpp"))
print(f"\nil2cpp_* exports: {len(il2cpp)}")

# 运行时解析最关键的 API
KEY = [
    "il2cpp_domain_get_assemblies",
    "il2cpp_assembly_get_image",
    "il2cpp_class_from_name",
    "il2cpp_class_from_il2cppclass",
    "il2cpp_class_get_methods",
    "il2cpp_class_get_method_from_name",
    "il2cpp_method_get_param_count",
    "il2cpp_runtime_invoke",
    "il2cpp_domain_get",
    "il2cpp_image_get_class",
    "il2cpp_image_get_class_count",
    "il2cpp_class_get_name",
    "il2cpp_class_get_namespace",
    "il2cpp_class_get_fields",
    "il2cpp_field_get_offset",
    "il2cpp_type_get_name",
]
print("\n=== 运行时解析关键 API 存在性 ===")
present = set(il2cpp)
for k in KEY:
    mark = "OK " if k in present else "MISS"
    print(f"  [{mark}] {k}")

# 也列出所有含 class/method/domain/image 的，便于选型
print("\n=== class/method/domain/image 相关导出（前 60）===")
rel = [n for n in il2cpp if any(w in n for w in ("class", "method", "domain", "image", "assembly"))]
for n in rel[:60]:
    print(f"  {n}")
print(f"  ... 共 {len(rel)} 个")
