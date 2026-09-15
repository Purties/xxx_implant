/* implant.c — 自研注入模块 POC（阶段 1a：il2cpp 运行时解析验证）
 *
 * 目标：在游戏进程内通过 il2cpp_* 导出 API 枚举全部类与方法，
 *       反查 5 个已验证钩子 RVA（UNPACKING_REPORT §5.7.1）对应的方法身份。
 * 判据：5/5 反查命中，且输出各方法的 (镜像, 类名, 方法名, 类序号, 方法序号)。
 *       若类序号与原版 DLL 的 typedef1514 标签吻合，则证明 typedef/序号
 *       可作为跨构建稳定解析键（彻底摆脱硬编码 RVA）。
 *
 * 反检测基线（POC 即遵守 STRATEGY_PIVOT §2.3 可做到的部分）：
 *   - 无任何产品名/构建号/作者路径字符串
 *   - 不落盘日志到游戏目录（结果写回本工具目录）
 *   - 不引用游戏函数名明文（目标以 RVA 数值表达）
 */
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdio.h>
#include <string.h>
#include <setjmp.h>

/* 枚举期崩溃恢复：VEH 把危险区异常 longjmp 回类循环安全点 */
static jmp_buf g_jmp;
static volatile LONG g_inDanger = 0;
static void *g_curKlass = NULL;

/* ---- 结果输出（非特征化文件名） ---- */
static const char *g_logPath = "c:\\workspace\\9-4#2\\implant\\out\\poc_result.log";
static const char *g_dumpPath = "c:\\workspace\\9-4#2\\implant\\out\\methods.tsv";
static FILE *g_log;
static FILE *g_dump;
static CRITICAL_SECTION g_cs;

static void logf_(const char *fmt, ...) {
    if (!g_log) return;
    EnterCriticalSection(&g_cs);
    va_list ap; va_start(ap, fmt);
    SYSTEMTIME st; GetLocalTime(&st);
    fprintf(g_log, "[%02u:%02u:%02u.%03u] ", st.wHour, st.wMinute, st.wSecond, st.wMilliseconds);
    vfprintf(g_log, fmt, ap);
    fputc('\n', g_log);
    fflush(g_log);
    va_end(ap);
    LeaveCriticalSection(&g_cs);
}

/* ---- il2cpp API 签名（仅 POC 所需子集） ---- */
typedef void *(*p_domain_get)(void);
typedef void *(*p_domain_get_assemblies)(void *domain, size_t *count);
typedef void *(*p_assembly_get_image)(void *assembly);
typedef size_t (*p_image_get_class_count)(void *image);
typedef void *(*p_image_get_class)(void *image, size_t index);
typedef const char *(*p_class_get_name)(void *klass);
typedef const char *(*p_class_get_namespace)(void *klass);
typedef void *(*p_class_get_methods)(void *klass, void **iter);
typedef const char *(*p_method_get_name)(void *method);
typedef int (*p_method_get_param_count)(void *method);
typedef const char *(*p_image_get_name)(void *image);

static p_domain_get             api_domain_get;
static p_domain_get_assemblies  api_domain_get_assemblies;
static p_assembly_get_image     api_assembly_get_image;
static p_image_get_class_count  api_image_get_class_count;
static p_image_get_class        api_image_get_class;
static p_class_get_name         api_class_get_name;
static p_class_get_namespace    api_class_get_namespace;
static p_class_get_methods      api_class_get_methods;
static p_method_get_name        api_method_get_name;
static p_method_get_param_count api_method_get_param_count;
static p_image_get_name         api_image_get_name;

static int resolve_api(HMODULE ga) {
    struct { const char *name; void **slot; } map[] = {
        { "il2cpp_domain_get",            (void **)&api_domain_get },
        { "il2cpp_domain_get_assemblies", (void **)&api_domain_get_assemblies },
        { "il2cpp_assembly_get_image",    (void **)&api_assembly_get_image },
        { "il2cpp_image_get_class_count", (void **)&api_image_get_class_count },
        { "il2cpp_image_get_class",       (void **)&api_image_get_class },
        { "il2cpp_class_get_name",        (void **)&api_class_get_name },
        { "il2cpp_class_get_namespace",   (void **)&api_class_get_namespace },
        { "il2cpp_class_get_methods",     (void **)&api_class_get_methods },
        { "il2cpp_method_get_name",       (void **)&api_method_get_name },
        { "il2cpp_method_get_param_count",(void **)&api_method_get_param_count },
        { "il2cpp_image_get_name",        (void **)&api_image_get_name },
    };
    for (size_t i = 0; i < sizeof(map)/sizeof(map[0]); i++) {
        *map[i].slot = (void *)GetProcAddress(ga, map[i].name);
        if (!*map[i].slot) { logf_("MISSING export: %s", map[i].name); return 0; }
    }
    return 1;
}

/* ---- 目标 RVA 双组（§5.2 旧 0902 行 / §5.7.1 新版 ba7b80fc） ----
 * 老版本游戏命中 O 组，新版本命中 N 组；命中即证明 il2cpp 运行时
 * 枚举能反查出钩子方法身份（类序号/方法序号=跨构建解析键候选）。
 */
struct target { const char *tag; const char *ver; DWORD64 rva; int found; };
static struct target g_targets[] = {
    { "V", "OLD", 0x11BE640, 0 }, { "V", "NEW", 0x12144F0, 0 },
    { "I", "OLD", 0x11BE670, 0 }, { "I", "NEW", 0x1214940, 0 },
    { "C", "OLD", 0x11BEF10, 0 }, { "C", "NEW", 0x1215270, 0 },
    { "D", "OLD", 0x1049B70, 0 }, { "D", "NEW", 0x10D74B0, 0 },
    { "U", "OLD", 0x1660650, 0 }, { "U", "NEW", 0x14DB0B0, 0 },
};
#define NTARGETS (sizeof(g_targets)/sizeof(g_targets[0]))

/* ---- 身份键表（跨构建稳定解析键，来自旧版现场捕获，已证实存在于元数据串表） ----
 * 名称（类哈希/方法哈希）为元数据内稳定标识；RVA 仅作验证基准。
 * 解析成功 = 按名称找到方法且其指针 == base+RVA。
 */
struct ident { const char *tag; const char *ver;
               const char *clsHash; const char *mtdHash;
               DWORD64 rva; void *resolved; };
static struct ident g_idents[] = {
    { "V", "OLD", "f46670bd6ea22817dec4b7ac9c5b7bccdc12d9bdca55d798ec278f4b77d917c",
                   "d4f1d9ba5f1bd5ee24bbe44d0916b19e4ac47142d72644eb413f409759c2fde", 0x11BE640, NULL },
    { "I", "OLD", "f46670bd6ea22817dec4b7ac9c5b7bccdc12d9bdca55d798ec278f4b77d917c",
                   "bcc2b2aa4d3e4bca953011745270a63118dd621f5cf6c8571e590152f5f219f", 0x11BE670, NULL },
    { "C", "OLD", "f46670bd6ea22817dec4b7ac9c5b7bccdc12d9bdca55d798ec278f4b77d917c",
                   "e174a2619425855250e3f20ebd706c11eb0b7b9abbdfa8e448768c2835313a0", 0x11BEF10, NULL },
    { "D", "OLD", "ac815ae99e729e8eaca2294e1428a4c8e8c039e628b5eedaf9ad76294699af7",
                   "d88bcb202e7f57be17f6306bbc1e0030dc947078cb4e023bb15be8e0fe7cd51", 0x1049B70, NULL },
    { "U", "OLD", "b6be5581803c58bcb4bb4580ce0a21e36b506d742cc5f1c8564bd768f92ce0c",
                   "Update", 0x1660650, NULL },
};
#define NIDENTS (sizeof(g_idents)/sizeof(g_idents[0]))

/* ---- 特征签名解析层（跨构建稳定：结构字段偏移 + 操作码骨架，掩码轮换字段） ----
 * 与身份键（哈希名，逐构建轮换）互补：哈希轮换但字段偏移/骨架不变。
 * sig 掩码：0x00-0xFF 精确字节，'?' 通配（RIP disp32 / 混淆 imm8 等逐构建轮换处）。
 */
struct sig { const char *tag; const char *mask; int len; DWORD64 expectRva;
             DWORD64 expectRvaNew;     /* 新版构建基准（§5.7.1），两版任一命中即 PASS */
             int wantParams;           /* >=0 则要求方法参数数==此值（运行时结构约束，跨构建稳定） */
             const char *sameClassAs;  /* 非空则要求命中方法与该 tag 同属一个类（结构约束消歧） */
             const char *callsTag;     /* 非空则要求命中方法体内前 256B 有 call 到该 tag 的方法 */
             int hits; void *firstPtr; void *firstKlass; };
static struct sig g_sigs[] = {
    /* 5 条签名由 tools/sig_design.py 从老/新两版 GA 逐字节 diff 自动掩码生成，
     * 两版各自唯一命中期望 RVA（跨构建唯一性已离线证明）。
     * C 序言通用（56B 前缀活体 108 命中），用"与 V 同类 + 体内 call I"结构约束收敛。 */
    /* wantParams：D=10（SetDamaged 极独特参数数，用于运行时消歧；-1=不约束） */
    { "V", "48 89 91 F8 00 00 00 0F B6 05 ? ? ? 05 ? ?", 16, 0x11BE640, 0x12144F0, -1, NULL, NULL, 0, NULL, NULL },
    { "I", "56 57 53 48 81 EC ? 01 00 00 44 0F 29 84 24 ? 01 00 00 0F 29 BC 24 ? 01 00 00 0F 29 B4 24 ? 01 00 00 66 0F 28 F2 66 0F 28 F9 48 89 CE 48 8D", 48, 0x11BE670, 0x1214940, -1, NULL, NULL, 0, NULL, NULL },
    { "C", "48 83 EC ? 48 8D 05 ? 00 00 00 48 89 44 24", 14, 0x11BEF10, 0x1215270, -1, "V", "I", 0, NULL, NULL },
    { "D", "41 57 41 56 41 55 41 54 56 57 55 53 B8 ? ? ? ? E8 ? ? ? FF 48 29 C4", 26, 0x1049B70, 0x10D74B0, 10, NULL, NULL, 0, NULL, NULL },
    { "U", "E9 0B 00 00 00 66 66 2E 0F 1F 84 00 00 00 00 00 56 57 53 48 81 EC ? ? 00 00 48 89 CE 48 8D 05 ? ? 00 00 48 89 84 24 ? ? 00 00 48 8D 0D ?", 48, 0x1660650, 0x14DB0B0, -1, NULL, NULL, 0, NULL, NULL },
};
#define NSIGS (sizeof(g_sigs)/sizeof(g_sigs[0]))

/* 约束型签名：先收集全部掩码命中候选，枚举结束后再解约束（不依赖方法遍历顺序）
 * C 用松掩码（~1800 命中），故缓冲上限需覆盖之；D 用 wantParams 即时过滤不缓冲。 */
struct sig;
#define MAX_CAND 4096
struct cand { void *ptr; void *klass; struct sig *sig; };
static struct cand g_cand[MAX_CAND]; static int g_ncand = 0;

static struct sig *sig_by_tag(const char *tag) {
    for (size_t i = 0; i < NSIGS; i++) if (!strcmp(g_sigs[i].tag, tag)) return &g_sigs[i];
    return NULL;
}

static int parse_hex_mask(const char *mask, BYTE *out, int maxn) {
    int n = 0; const char *p = mask;
    while (*p && n < maxn) {
        while (*p == ' ') p++;
        if (!*p) break;
        if (p[0] == '?') { out[n++] = 0; p += 1; }
        else { unsigned v; sscanf(p, "%2x", &v); out[n++] = (BYTE)v; p += 2; }
    }
    return n;
}
static int mask_match(const BYTE *data, const char *mask) {
    int i = 0; const char *p = mask;
    for (; *p; ) {
        while (*p == ' ') p++;
        if (!*p) break;
        if (p[0] == '?') { i++; p += 1; continue; }
        unsigned v; sscanf(p, "%2x", &v);
        if (data[i] != (BYTE)v) return 0;
        i++; p += 2;
    }
    return 1;
}

/* MethodInfo 首字段即 methodPointer（Unity il2cpp 布局） */
static void *method_pointer(void *method) { return *(void **)method; }

/* ---- 最小钩子引擎（14 字节绝对 detour，两指令长边界） ----
 * SetVelocity 序言 = 7B(mov [rcx+0f8],rdx) + 7B(movzx/mov) = 14B，恰好容纳
 * FF 25 00 00 00 00 + qword。trampoline 保存原 14B + 跳回。
 */
typedef void (*fn2)(void *, void *);
static volatile LONG g_hookHits = 0;
static fn2 g_trampV = NULL;

static void * __fastcall hook_V(void *self, void *val) {
    InterlockedIncrement(&g_hookHits);
    g_trampV(self, val);
    return NULL;
}

/* 在 target±1GB 内分配 trampoline（64KB 对齐步进） */
static void *alloc_near(void *target, SIZE_T size) {
    BYTE *t = (BYTE *)target;
    BYTE *lo = (BYTE *)(((DWORD64)t - 0x40000000) & ~0xFFFFull);  /* 64KB 对齐 */
    BYTE *hi = (BYTE *)(((DWORD64)t + 0x40000000) & ~0xFFFFull);
    for (BYTE *a = lo; a + size < hi; a += 0x10000) {
        void *p = VirtualAlloc(a, size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
        if (p == a) return p;
        if (p) VirtualFree(p, 0, MEM_RELEASE);   /* 落点偏离，放弃 */
    }
    return NULL;
}

/* 安装 14 字节 detour。要求目标序言 = 7B 非RIP + 7B movzx RIP（SetVelocity 族）：
 *   [0]  48 89 81 xx 00 00 00     mov [rcx+disp32], rdx
 *   [7]  0F B6 modrm disp32       movzx eax, byte ptr [rip+disp32]
 * trampoline 内修正 movzx 的 disp32（重定位 RIP 相对寻址）。 */
static int install_detour(void *target, void *hook, fn2 *trampOut) {
    BYTE *t = (BYTE *)target;
    if (!(t[0]==0x48 && t[1]==0x89 && (t[2]&0xC7)==0x81 &&   /* mov [rcx+disp32], r64 */
          t[7]==0x0F && t[8]==0xB6 && (t[9]&0xC7)==0x05)) { /* movzx eax, byte [rip+disp32] */
        logf_("detour: unexpected prologue %02X %02X %02X / %02X %02X %02X",
              t[0],t[1],t[2],t[7],t[8],t[9]);
        return 0;
    }
    DWORD old;
    if (!VirtualProtect(t, 14, PAGE_EXECUTE_READWRITE, &old)) return 0;
    void *tramp = alloc_near(t, 64);
    if (!tramp) { VirtualProtect(t, 14, old, &old); return 0; }
    memcpy(tramp, t, 14);
    *(DWORD *)((BYTE *)tramp + 10) += (DWORD)((t + 14) - ((BYTE *)tramp + 14)); /* RIP 修正 */
    BYTE back[] = { 0xFF, 0x25, 0, 0, 0, 0 };
    memcpy((BYTE *)tramp + 14, back, 6);
    *(DWORD64 *)((BYTE *)tramp + 20) = (DWORD64)(t + 14);   /* 跳回 */
    BYTE jmp[] = { 0xFF, 0x25, 0, 0, 0, 0 };
    memcpy(t, jmp, 6);
    *(DWORD64 *)(t + 6) = (DWORD64)hook;                    /* 跳钩子 */
    VirtualProtect(t, 14, old, &old);
    FlushInstructionCache(GetCurrentProcess(), t, 14);
    *trampOut = (fn2)tramp;
    return 1;
}

static DWORD WINAPI worker(LPVOID param) {
    (void)param;
    size_t abortClass = 0;
    logf_("worker start, pid=%lu", GetCurrentProcessId());

    /* 1) 等待 GameAssembly.dll */
    HMODULE ga = NULL;
    for (int i = 0; i < 600 && !ga; i++) {          /* 最长等 5 分钟 */
        ga = GetModuleHandleW(L"GameAssembly.dll");
        if (!ga) Sleep(500);
    }
    if (!ga) { logf_("FATAL: GameAssembly.dll never appeared"); return 1; }
    logf_("GameAssembly.dll base=%p", (void *)ga);

    /* 2) 等待 il2cpp 运行时就绪（domain 非空） */
    if (!resolve_api(ga)) return 2;
    void *domain = NULL;
    for (int i = 0; i < 600 && !domain; i++) {
        domain = api_domain_get();
        if (!domain) Sleep(500);
    }
    if (!domain) { logf_("FATAL: il2cpp domain never ready"); return 3; }
    logf_("il2cpp domain ready");

    /* 3) 目标绝对地址 */
    for (size_t t = 0; t < NTARGETS; t++)
        logf_("target[%s/%s] = base+0x%llX = %p", g_targets[t].tag, g_targets[t].ver,
             g_targets[t].rva, (void *)((BYTE *)ga + g_targets[t].rva));

    /* 3b) 打开全量方法导出文件 */
    g_dump = fopen(g_dumpPath, "w");
    if (g_dump) fputs("rva\timage\tnamespace\tclass\tmethod\tparams\n", g_dump);
    else logf_("WARN: cannot open dump file");

    /* 4) 枚举 assemblies → images → classes → methods，反查目标 */
    size_t nAsm = 0;
    void **asms = (void **)api_domain_get_assemblies(domain, &nAsm);
    logf_("assemblies: %zu", nAsm);

    size_t totalClasses = 0, totalMethods = 0, skipped = 0;
    DWORD64 t0 = GetTickCount64();

    /* GameAssembly 映像大小（判定方法指针归属） */
    DWORD e_lfanew = *(DWORD *)((BYTE *)ga + 0x3C);
    DWORD sizeOfImage = *(DWORD *)((BYTE *)ga + e_lfanew + 4 + 20 + 56);
    BYTE *gaEnd = (BYTE *)ga + sizeOfImage;

    /* 整轮枚举置于单一安全点下：游戏初始化未完成时任何 il2cpp API 都可能 AV，
     * 触发则放弃剩余枚举（身份键若已解析仍有效），避免崩溃宿主进程 */
    if (InterlockedCompareExchange(&g_inDanger, 1, 0) != 0) Sleep(1);
    if (setjmp(g_jmp) != 0) {
        g_inDanger = 0;
        logf_("enumeration ABORTED by exception at class %zu (partial: classes=%zu methods=%zu)",
              abortClass, totalClasses, totalMethods);
        goto after_enum;
    }

    for (size_t a = 0; a < nAsm; a++) {
        void *image = api_assembly_get_image(asms[a]);
        if (!image) continue;
        const char *iname = api_image_get_name ? api_image_get_name(image) : "?";
        size_t nCls = api_image_get_class_count(image);
        for (size_t c = 0; c < nCls; c++) {
            abortClass = c;
            void *klass = api_image_get_class(image, c);
            if (!klass) continue;
            totalClasses++;
            const char *cname = api_class_get_name(klass);
            const char *cns = api_class_get_namespace(klass);

            /* 该类是否命中任一身份键的类哈希 */
            int clsMatch[NIDENTS]; int anyCls = 0;
            for (size_t k = 0; k < NIDENTS; k++) {
                clsMatch[k] = (!g_idents[k].resolved && strcmp(cname, g_idents[k].clsHash) == 0);
                anyCls |= clsMatch[k];
            }

            void *iter = NULL;
            void *m;
            size_t mi = 0;
            while ((m = api_class_get_methods(klass, &iter))) {
                totalMethods++;
                void *fp = method_pointer(m);
                const char *mname = api_method_get_name(m);
                int nargs = api_method_get_param_count(m);
                /* 全量导出：属于 GameAssembly 映像的方法（TSV） */
                if (g_dump && fp && (BYTE *)fp >= (BYTE *)ga && (BYTE *)fp < gaEnd)
                    fprintf(g_dump, "0x%llX\t%s\t%s\t%s\t%s\t%d\n",
                            (DWORD64)((BYTE *)fp - (BYTE *)ga), iname, cns, cname, mname, nargs);
                for (size_t t = 0; t < NTARGETS; t++) {
                    if (!g_targets[t].found &&
                        fp == (void *)((BYTE *)ga + g_targets[t].rva)) {
                        g_targets[t].found = 1;
                        logf_("HIT[%s/%s] rva=0x%llX class[%zu]=%s.%s method[%zu]=%s params=%d ptr=%p",
                             g_targets[t].tag, g_targets[t].ver, g_targets[t].rva,
                             c, cns, cname, mi, mname, nargs, fp);
                    }
                }
                /* 特征签名解析：掩码匹配方法序言（跨构建稳定结构特征） */
                if (fp && (BYTE *)fp >= (BYTE *)ga && (BYTE *)fp < gaEnd) {
                    for (size_t s = 0; s < NSIGS; s++) {
                        if (!mask_match((BYTE *)fp, g_sigs[s].mask)) continue;
                        if (g_sigs[s].wantParams >= 0 && nargs != g_sigs[s].wantParams) continue;
                        if (g_sigs[s].sameClassAs || g_sigs[s].callsTag) {
                            /* 约束型：收集候选，枚举后解约束 */
                            if (g_ncand < MAX_CAND) {
                                g_cand[g_ncand].ptr = fp;
                                g_cand[g_ncand].klass = klass;
                                g_cand[g_ncand].sig = (struct sig *)&g_sigs[s];
                                g_ncand++;
                            }
                        } else {
                            g_sigs[s].hits++;
                            if (!g_sigs[s].firstPtr) {
                                g_sigs[s].firstPtr = fp;
                                g_sigs[s].firstKlass = klass;
                            }
                        }
                    }
                }
                /* 身份键解析：按类哈希+方法哈希定位 */
                if (anyCls) {
                    for (size_t k = 0; k < NIDENTS; k++) {
                        if (clsMatch[k] && strcmp(mname, g_idents[k].mtdHash) == 0) {
                            g_idents[k].resolved = fp;
                            logf_("RESOLVE[%s/%s] byName class=%s method=%s -> ptr=%p rva=0x%llX",
                                 g_idents[k].tag, g_idents[k].ver, g_idents[k].clsHash,
                                 g_idents[k].mtdHash, fp, (DWORD64)((BYTE *)fp - (BYTE *)ga));
                        }
                    }
                }
                mi++;
            }
        }
    }
    g_inDanger = 0;   /* 整轮枚举安全结束 */
after_enum:
    if (g_dump) { fflush(g_dump); fclose(g_dump); g_dump = NULL; logf_("methods.tsv written"); }

    logf_("enumeration done in %llu ms: classes=%zu methods=%zu",
         GetTickCount64() - t0, totalClasses, totalMethods);

    /* 5) 判定 */
    int hits = 0, hitsOld = 0, hitsNew = 0;
    for (size_t t = 0; t < NTARGETS; t++) {
        logf_("verdict[%s/%s] rva=0x%llX -> %s", g_targets[t].tag, g_targets[t].ver,
             g_targets[t].rva, g_targets[t].found ? "FOUND" : "MISS");
        hits += g_targets[t].found;
        if (!strcmp(g_targets[t].ver, "OLD")) hitsOld += g_targets[t].found;
        else hitsNew += g_targets[t].found;
    }
    logf_("VERDICT: %d/%d (OLD=%d/5, NEW=%d/5)", hits, (int)NTARGETS, hitsOld, hitsNew);

    /* 6) 身份键解析验证：按名称解析出的指针应等于 base+RVA */
    int ok = 0;
    for (size_t k = 0; k < NIDENTS; k++) {
        void *expect = (BYTE *)ga + g_idents[k].rva;
        int match = (g_idents[k].resolved == expect);
        ok += match;
        logf_("IDENT[%s/%s] byName=%p expect(base+0x%llX)=%p -> %s",
             g_idents[k].tag, g_idents[k].ver, g_idents[k].resolved,
             g_idents[k].rva, expect, match ? "MATCH" : "MISMATCH");
    }
    logf_("IDENT-VERDICT: %d/%d", ok, (int)NIDENTS);

    /* 6a) 解约束型签名（C：与 V 同类 且 体内 call I） */
    for (int i = 0; i < g_ncand; i++) {
        struct sig *sg = g_cand[i].sig;
        if (sg->sameClassAs) {
            struct sig *anchor = sig_by_tag(sg->sameClassAs);
            if (!anchor || anchor->firstKlass != g_cand[i].klass) continue;
        }
        if (sg->callsTag) {
            struct sig *callee = sig_by_tag(sg->callsTag);
            if (!callee || !callee->firstPtr) continue;
            BYTE *fb = (BYTE *)g_cand[i].ptr;
            /* 扫描窗钳制到函数尾（防越界"看进"邻居函数的 call）：
             * RtlLookupFunctionEntry 查的就是本进程内存 .pdata */
            DWORD64 base = 0;
            RUNTIME_FUNCTION *rf = RtlLookupFunctionEntry((DWORD64)fb, &base, NULL);
            DWORD64 fend = rf ? (DWORD64)base + rf->EndAddress : (DWORD64)fb + 256;
            DWORD64 lim = (DWORD64)fb + 256 < fend ? (DWORD64)fb + 256 : fend;
            int found = 0;
            for (BYTE *q = fb; q + 5 <= (BYTE *)lim; q++) {
                if (q[0] != 0xE8) continue;
                int rel = *(int *)(q + 1);
                if (q + 5 + rel == (BYTE *)callee->firstPtr) { found = 1; break; }
            }
            if (!found) continue;
        }
        sg->hits++;
        if (!sg->firstPtr) { sg->firstPtr = g_cand[i].ptr; sg->firstKlass = g_cand[i].klass; }
    }

    /* 6b) 特征签名判定：hits==1 即解析成功（新构建 RVA 本就不在旧基线表内）；
     *     命中已知基线额外标 KNOWN 作回归佐证，未命中基线标 RESOLVED-NEW。 */
    int sigOk = 0;
    for (size_t s = 0; s < NSIGS; s++) {
        DWORD64 got = g_sigs[s].firstPtr ? (DWORD64)((BYTE *)g_sigs[s].firstPtr - (BYTE *)ga) : 0;
        int resolved = (g_sigs[s].hits == 1);
        int known = resolved && (got == g_sigs[s].expectRva || got == g_sigs[s].expectRvaNew);
        sigOk += resolved;
        logf_("SIG[%s] hits=%d rva=0x%llX -> %s",
             g_sigs[s].tag, g_sigs[s].hits, got,
             !resolved ? (g_sigs[s].hits == 0 ? "NO-HIT" : "AMBIGUOUS")
                       : (known ? "RESOLVED-KNOWN" : "RESOLVED-NEW"));
    }
    logf_("SIG-VERDICT: %d/%d", sigOk, (int)NSIGS);

    /* 7) 端到端功能自测（默认关闭！会改写游戏活代码，仅在隔离/离线验证时开启）
     *    开启方式：环境变量 IMPLANT_HOOKTEST=1 */
    {
        char envb[8] = {0};
        int enable = GetEnvironmentVariableA("IMPLANT_HOOKTEST", envb, sizeof(envb)) > 0;
        if (!enable) logf_("HOOKTEST disabled (set IMPLANT_HOOKTEST=1 to enable)");
        if (enable && g_idents[0].resolved) {
            void *target = g_idents[0].resolved;               /* SetVelocity */
            BYTE *fake = VirtualAlloc(NULL, 0x2000, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
            if (fake && install_detour(target, (void *)hook_V, &g_trampV)) {
                fn2 callV = (fn2)target;                        /* 经钩子路径 */
                callV(fake, (void *)(DWORD64)0x1234);
                DWORD64 v = *(DWORD64 *)(fake + 0xF8);
                BYTE flag = fake[0xF4];
                logf_("HOOKTEST hits=%ld f8=0x%llX f4=0x%02X -> %s",
                     g_hookHits, v, flag,
                     (g_hookHits == 1 && v == 0x1234) ? "PASS" : "FAIL");
            } else {
                logf_("HOOKTEST: install failed (fake=%p)", (void *)fake);
            }
        }
    }
    return 0;
}

/* 顶层异常兜底：
 * - 枚举危险区内（g_inDanger）的 AV -> longjmp 回本类安全点，跳过该类
 * - 其余异常留痕后继续搜索
 * 注：longjmp 会放弃 g_dump 的 stdio 缓冲（置 NULL 防后续 fprintf 用坏状态） */
static LONG WINAPI veh(EXCEPTION_POINTERS *ep) {
    DWORD code = ep->ExceptionRecord->ExceptionCode;
    if (code == 0x40010006 /*DBG_PRINTEXCEPTION_C*/ || code == 0x406D1388 /*SetThreadName*/)
        return EXCEPTION_CONTINUE_SEARCH;   /* 游戏调试输出，忽略 */
    if (g_inDanger && (code == EXCEPTION_ACCESS_VIOLATION ||
                       code == EXCEPTION_ILLEGAL_INSTRUCTION ||
                       code == EXCEPTION_IN_PAGE_ERROR)) {
        g_inDanger = 0;
        g_dump = NULL;
        longjmp(g_jmp, 1);
    }
    logf_("UNHANDLED EXCEPTION code=0x%08lX addr=%p",
         code, ep->ExceptionRecord->ExceptionAddress);
    return EXCEPTION_CONTINUE_SEARCH;
}

BOOL WINAPI DllMain(HINSTANCE hinst, DWORD reason, LPVOID reserved) {
    (void)hinst; (void)reserved;
    if (reason == DLL_PROCESS_ATTACH) {
        InitializeCriticalSection(&g_cs);
        char dir[MAX_PATH];
        GetModuleFileNameA(NULL, dir, MAX_PATH);   /* 记录宿主，诊断用 */
        g_log = fopen(g_logPath, "a");
        logf_("==== implant attached into: %s", dir);
        AddVectoredExceptionHandler(1, veh);
        HANDLE th = CreateThread(NULL, 0, worker, NULL, 0, NULL);
        if (th) CloseHandle(th);
    }
    return TRUE;
}
