# fingerprint_recon.py - 阶段0-B：枚举原版注入 DLL 的可识别特征（反检测需求面）
import re, sys

DUMP = r"c:\workspace\9-4#2\xxx\analysis\memscan\region_0_0x269C000.bin"
OUT = r"c:\workspace\9-4#2\xxx\analysis\fingerprint_recon.txt"

data = open(DUMP, "rb").read()
pat = re.compile(rb"[\x20-\x7e]{5,}")
strings = [(m.start(), m.group().decode("ascii", "replace")) for m in pat.finditer(data)]
pat16 = re.compile(rb"(?:[\x20-\x7e]\x00){5,}")
strings += [(m.start(), "[W]" + m.group().decode("utf-16-le", "replace")) for m in pat16.finditer(data)]

L = []
def sec(title): L.append(f"\n## {title}")
def emit(hits, cap=40):
    for off, s in hits[:cap]:
        L.append(f"  @{off:#010x}  {s[:180]}")
    if len(hits) > cap: L.append(f"  ... 另 {len(hits)-cap} 条")

sec("1. 构建身份串（最强指纹：唯一、稳定、易扫描）")
emit([(o, s) for o, s in strings if re.search(r"skill-manager|r212|bypassngs|bypass_build_id|runtime_dump_rva|20260\d\d", s)])

sec("2. 作者源码路径泄漏（编译期 __FILE__ 残留）")
emit([(o, s) for o, s in strings if re.search(r"[A-Za-z]:\\|\\code\\|\.cpp|\.h\b", s) and "imgui" in s.lower() or "E:\\" in s or "e:\\" in s])

sec("3. 命名对象/IPC（进程间可见，行为扫描可命中）")
emit([(o, s) for o, s in strings if re.search(r"Local\\|Global\\|Session\\|Mutex|Event\\|Pipe", s)])

sec("4. 日志/诊断文件名（磁盘落盘特征，hook_artifacts 目录）")
emit([(o, s) for o, s in strings if re.search(r"\.log|hook_artifacts|diagnostics|anti_macro_packets", s)])

sec("5. 网络端点（授权/租约通道）")
emit([(o, s) for o, s in strings if re.search(r"/v3/|/api/|implant|lease|redeem|heartbeat|nonce", s)])

sec("6. 引用的模块名（模块列表/字符串扫描可见）")
emit([(o, s) for o, s in strings if re.search(r"\.dll|\.exe", s, re.I) and len(s) < 60])

sec("7. 版本表哈希区（0x183FC0 起 5×64B SHA-256 ASCII，全库唯一锚点）")
blk = data[0x183FC0:0x183FC0+5*80]
for i in range(5):
    row = blk[i*80:(i+1)*80].split(b"\x00")[0]
    L.append(f"  hash[{i}] = {row.decode('ascii','replace')[:64]}")

sec("8. 游戏方法名/钩子名（与游戏函数同名，语义指纹）")
emit([(o, s) for o, s in strings if s in ("SetVelocity","SetImpactNext","SetDamaged","DoCombatStep","DoActiveSkill","IsSkillAvailable","NpcDialog","SendDropPickUpRequest","GetLoginStep") or re.fullmatch(r"[A-Z][A-Za-z]{6,}", s) and 0x160000 < o < 0x190000][:30])

sec("9. 配置键名（## / JSON 键，功能语义指纹）")
emit([(o, s) for o, s in strings if s.startswith("##") or re.match(r"^[a-z_]{6,}$", s) and any(k in s for k in ("invincible","attack","hunt","auto_","macro","walk"))])

open(OUT, "w", encoding="utf-8").write(f"# 原版注入 DLL 可识别特征枚举（转储 {len(data):#x}B）\n" + "\n".join(L))
print(f"written: {OUT}", file=sys.stderr)
print(f"sections: {len([l for l in L if l.startswith(chr(10)+'##') or l.startswith('## ')])}", file=sys.stderr)
