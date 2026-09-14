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

/* ---- 结果输出（非特征化文件名） ---- */
static const char *g_logPath = "c:\\workspace\\9-4#2\\implant\\out\\poc_result.log";
static const char *g_dumpPath = "c:\\workspace\\9-4#2\\implant\\out\\methods.tsv";
static FILE *g_log;
static FILE *g_dump;
static CRITICAL_SECTION g_cs;

static void logf(const char *fmt, ...) {
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
        if (!*map[i].slot) { logf("MISSING export: %s", map[i].name); return 0; }
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

/* MethodInfo 首字段即 methodPointer（Unity il2cpp 布局） */
static void *method_pointer(void *method) { return *(void **)method; }

static DWORD WINAPI worker(LPVOID param) {
    (void)param;
    logf("worker start, pid=%lu", GetCurrentProcessId());

    /* 1) 等待 GameAssembly.dll */
    HMODULE ga = NULL;
    for (int i = 0; i < 600 && !ga; i++) {          /* 最长等 5 分钟 */
        ga = GetModuleHandleW(L"GameAssembly.dll");
        if (!ga) Sleep(500);
    }
    if (!ga) { logf("FATAL: GameAssembly.dll never appeared"); return 1; }
    logf("GameAssembly.dll base=%p", (void *)ga);

    /* 2) 等待 il2cpp 运行时就绪（domain 非空） */
    if (!resolve_api(ga)) return 2;
    void *domain = NULL;
    for (int i = 0; i < 600 && !domain; i++) {
        domain = api_domain_get();
        if (!domain) Sleep(500);
    }
    if (!domain) { logf("FATAL: il2cpp domain never ready"); return 3; }
    logf("il2cpp domain ready");

    /* 3) 目标绝对地址 */
    for (size_t t = 0; t < NTARGETS; t++)
        logf("target[%s/%s] = base+0x%llX = %p", g_targets[t].tag, g_targets[t].ver,
             g_targets[t].rva, (void *)((BYTE *)ga + g_targets[t].rva));

    /* 3b) 打开全量方法导出文件 */
    g_dump = fopen(g_dumpPath, "w");
    if (g_dump) fputs("rva\timage\tnamespace\tclass\tmethod\tparams\n", g_dump);
    else logf("WARN: cannot open dump file");

    /* 4) 枚举 assemblies → images → classes → methods，反查目标 */
    size_t nAsm = 0;
    void **asms = (void **)api_domain_get_assemblies(domain, &nAsm);
    logf("assemblies: %zu", nAsm);

    size_t totalClasses = 0, totalMethods = 0;
    DWORD64 t0 = GetTickCount64();

    /* GameAssembly 映像大小（判定方法指针归属） */
    DWORD e_lfanew = *(DWORD *)((BYTE *)ga + 0x3C);
    DWORD sizeOfImage = *(DWORD *)((BYTE *)ga + e_lfanew + 4 + 20 + 56);
    BYTE *gaEnd = (BYTE *)ga + sizeOfImage;

    for (size_t a = 0; a < nAsm; a++) {
        void *image = api_assembly_get_image(asms[a]);
        if (!image) continue;
        const char *iname = api_image_get_name ? api_image_get_name(image) : "?";
        size_t nCls = api_image_get_class_count(image);
        for (size_t c = 0; c < nCls; c++) {
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
                        logf("HIT[%s/%s] rva=0x%llX class[%zu]=%s.%s method[%zu]=%s params=%d ptr=%p",
                             g_targets[t].tag, g_targets[t].ver, g_targets[t].rva,
                             c, cns, cname, mi, mname, nargs, fp);
                    }
                }
                /* 身份键解析：按类哈希+方法哈希定位 */
                if (anyCls) {
                    for (size_t k = 0; k < NIDENTS; k++) {
                        if (clsMatch[k] && strcmp(mname, g_idents[k].mtdHash) == 0) {
                            g_idents[k].resolved = fp;
                            logf("RESOLVE[%s/%s] byName class=%s method=%s -> ptr=%p rva=0x%llX",
                                 g_idents[k].tag, g_idents[k].ver, g_idents[k].clsHash,
                                 g_idents[k].mtdHash, fp, (DWORD64)((BYTE *)fp - (BYTE *)ga));
                        }
                    }
                }
                mi++;
            }
        }
    }
    if (g_dump) { fflush(g_dump); fclose(g_dump); g_dump = NULL; logf("methods.tsv written"); }

    logf("enumeration done in %llu ms: classes=%zu methods=%zu",
         GetTickCount64() - t0, totalClasses, totalMethods);

    /* 5) 判定 */
    int hits = 0, hitsOld = 0, hitsNew = 0;
    for (size_t t = 0; t < NTARGETS; t++) {
        logf("verdict[%s/%s] rva=0x%llX -> %s", g_targets[t].tag, g_targets[t].ver,
             g_targets[t].rva, g_targets[t].found ? "FOUND" : "MISS");
        hits += g_targets[t].found;
        if (!strcmp(g_targets[t].ver, "OLD")) hitsOld += g_targets[t].found;
        else hitsNew += g_targets[t].found;
    }
    logf("VERDICT: %d/%d (OLD=%d/5, NEW=%d/5)", hits, (int)NTARGETS, hitsOld, hitsNew);

    /* 6) 身份键解析验证：按名称解析出的指针应等于 base+RVA */
    int ok = 0;
    for (size_t k = 0; k < NIDENTS; k++) {
        void *expect = (BYTE *)ga + g_idents[k].rva;
        int match = (g_idents[k].resolved == expect);
        ok += match;
        logf("IDENT[%s/%s] byName=%p expect(base+0x%llX)=%p -> %s",
             g_idents[k].tag, g_idents[k].ver, g_idents[k].resolved,
             g_idents[k].rva, expect, match ? "MATCH" : "MISMATCH");
    }
    logf("IDENT-VERDICT: %d/%d", ok, (int)NIDENTS);
    return 0;
}

/* 顶层异常兜底：崩溃留痕便于现场诊断 */
static LONG WINAPI veh(EXCEPTION_POINTERS *ep) {
    logf("UNHANDLED EXCEPTION code=0x%08lX addr=%p",
         ep->ExceptionRecord->ExceptionCode, ep->ExceptionRecord->ExceptionAddress);
    return EXCEPTION_CONTINUE_SEARCH;
}

BOOL WINAPI DllMain(HINSTANCE hinst, DWORD reason, LPVOID reserved) {
    (void)hinst; (void)reserved;
    if (reason == DLL_PROCESS_ATTACH) {
        InitializeCriticalSection(&g_cs);
        char dir[MAX_PATH];
        GetModuleFileNameA(NULL, dir, MAX_PATH);   /* 记录宿主，诊断用 */
        g_log = fopen(g_logPath, "a");
        logf("==== implant attached into: %s", dir);
        AddVectoredExceptionHandler(1, veh);
        HANDLE th = CreateThread(NULL, 0, worker, NULL, 0, NULL);
        if (th) CloseHandle(th);
    }
    return TRUE;
}
