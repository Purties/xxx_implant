# feature_baseline.py - 阶段0-A：从注入 DLL 转储提取完整功能指纹，建立需求基线
# 输出 analysis/feature_baseline.txt（供人工分级）与 feature_strings.tsv（全量字符串+偏移）
import re, sys, collections

DUMP = r"c:\workspace\9-4#2\xxx\analysis\memscan\region_0_0x269C000.bin"
OUT_TXT = r"c:\workspace\9-4#2\xxx\analysis\feature_baseline.txt"
OUT_TSV = r"c:\workspace\9-4#2\xxx\analysis\feature_strings.tsv"

data = open(DUMP, "rb").read()
print(f"dump size: {len(data):#x}", file=sys.stderr)

# ASCII >= 5
pat = re.compile(rb"[\x20-\x7e]{5,}")
strings = [(m.start(), m.group().decode("ascii", "replace")) for m in pat.finditer(data)]
print(f"total ascii strings: {len(strings)}", file=sys.stderr)

# UTF-16LE >= 5（宽字符串，C#/.NET 风格日志常见）
pat16 = re.compile(rb"(?:[\x20-\x7e]\x00){5,}")
strings16 = [(m.start(), m.group().decode("utf-16-le", "replace")) for m in pat16.finditer(data)]
print(f"total utf16 strings: {len(strings16)}", file=sys.stderr)

all_strings = [(off, s, "A") for off, s in strings] + [(off, s, "W") for off, s in strings16]
all_strings.sort()

# 全量 TSV
with open(OUT_TSV, "w", encoding="utf-8") as f:
    f.write("offset\tenc\tstring\n")
    for off, s, enc in all_strings:
        f.write(f"{off:#010x}\t{enc}\t{s}\n")
print(f"written: {OUT_TSV}", file=sys.stderr)

# 功能分类关键词（基于 §4.1 注入侧能力清单扩展）
CATS = collections.OrderedDict([
    ("技能管理", ["skill", "Skill", "cooldown", "buff", "attack", "combo"]),
    ("无敌/伤害", ["invincible", "SetDamaged", "damaged", "SetVelocity", "velocity", "SetImpactNext", "impact", "hp", "guard"]),
    ("战斗步进", ["DoCombatStep", "combat", "step"]),
    ("输入", ["input", "Input", "keyboard", "key_", "Update rejected", "prologue"]),
    ("自动移动/寻路", ["move", "Move", "path", "Path", "walk", "jump", "ladder", "rope", "portal", "topology"]),
    ("自动登录", ["login", "Login", "account", "password", "character", "channel", "auto_login"]),
    ("NPC对话", ["npc", "NPC", "dialog", "talk", "quest"]),
    ("反宏对抗", ["macro", "Macro", "anti", "detect", "captcha", "verify"]),
    ("掉线观测", ["disconnect", "reconnect", "socket", "timeout"]),
    ("消耗品", ["potion", "consume", "item", "inventory"]),
    ("字符串/技能表导出", ["export", "dump", "table", "string_table"]),
    ("安全租约/授权", ["lease", "redeem", "license", "authorize", "heartbeat", "bypass"]),
    ("ImGui/菜单", ["imgui", "ImGui", "menu", "overlay", "kiero", "Present", "render"]),
    ("MinHook/钩子框架", ["MH_", "minhook", "hook", "trampoline", "detour"]),
    ("版本表/RVA解析", ["dump11", "typedef", "ordinal", "rva", "RVA", "GameAssembly", "sha256", "metadata", "version_table"]),
    ("日志/诊断", ["log", ".log", "hook_artifacts", "diagnostics", "trace", "error", "failed"]),
])

lines = []
lines.append(f"# 注入 DLL 功能指纹基线（转储 {len(data):#x} 字节，ASCII {len(strings)} + UTF16 {len(strings16)} 条字符串）\n")

seen = set()
for cat, keys in CATS.items():
    hits = []
    for off, s, enc in all_strings:
        if any(k in s for k in keys):
            if (off, s) not in seen:
                hits.append((off, enc, s))
                seen.add((off, s))
    lines.append(f"\n## {cat}  ({len(hits)} 条)")
    for off, enc, s in hits[:80]:
        lines.append(f"  [{enc}] @{off:#010x}  {s[:160]}")
    if len(hits) > 80:
        lines.append(f"  ... 另 {len(hits)-80} 条（见 feature_strings.tsv）")

# 未分类的可疑长字符串（可能是功能名/日志格式串）
lines.append("\n\n## 未分类字符串样本（长度>=12，前 200 条，人工筛查用）")
n = 0
for off, s, enc in all_strings:
    if (off, s) in seen:
        continue
    if len(s) >= 12 and not re.fullmatch(r"[0-9a-fA-FxX._\-+/\\: ]+", s):
        lines.append(f"  [{enc}] @{off:#010x}  {s[:160]}")
        n += 1
        if n >= 200:
            break

open(OUT_TXT, "w", encoding="utf-8").write("\n".join(lines))
print(f"written: {OUT_TXT}", file=sys.stderr)
