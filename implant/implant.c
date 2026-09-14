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

/* ---- 结果输出（非特征化文件名） ---- */
static const char *g_logPath = "c:\\workspace\\9-4#2\\implant\\out\\poc_result.log";
static FILE *g_log;
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
typedef void *(*p_class_from_name)(void *image, const char *ns, const char *name);

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
    };
    for (size_t i = 0; i < sizeof(map)/sizeof(map[0]); i++) {
        *map[i].slot = (void *)GetProcAddress(ga, map[i].name);
        if (!*map[i].slot) { logf("MISSING export: %s", map[i].name); return 0; }
    }
    return 1;
}

/* ---- 5 个已验证钩子 RVA（§5.7.1，新版 GA ba7b80fc） ---- */
struct target { const char *tag; DWORD64 rva; int found; };
static struct target g_targets[] = {
    { "V", 0x12144F0, 0 },  /* SetVelocity   */
    { "I", 0x1214940, 0 },  /* SetImpactNext */
    { "C", 0x1215270, 0 },  /* DoCombatStep  */
    { "D", 0x10D74B0, 0 },  /* SetDamaged    */
    { "U", 0x14DB0B0, 0 },  /* input Update  */
};
#define NTARGETS (sizeof(g_targets)/sizeof(g_targets[0]))

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
        logf("target[%s] = base+0x%llX = %p", g_targets[t].tag,
             g_targets[t].rva, (void *)((BYTE *)ga + g_targets[t].rva));

    /* 4) 枚举 assemblies → images → classes → methods，反查目标 */
    size_t nAsm = 0;
    void **asms = (void **)api_domain_get_assemblies(domain, &nAsm);
    logf("assemblies: %zu", nAsm);

    size_t totalClasses = 0, totalMethods = 0;
    DWORD64 t0 = GetTickCount64();

    for (size_t a = 0; a < nAsm; a++) {
        void *image = api_assembly_get_image(asms[a]);
        if (!image) continue;
        size_t nCls = api_image_get_class_count(image);
        for (size_t c = 0; c < nCls; c++) {
            void *klass = api_image_get_class(image, c);
            if (!klass) continue;
            totalClasses++;
            const char *cname = "?", *cns = "?";
            __try { cname = api_class_get_name(klass); } __except (EXCEPTION_EXECUTE_HANDLER) {}
            __try { cns = api_class_get_namespace(klass); } __except (EXCEPTION_EXECUTE_HANDLER) {}

            void *iter = NULL;
            void *m;
            size_t mi = 0;
            while ((m = api_class_get_methods(klass, &iter))) {
                totalMethods++;
                void *fp = method_pointer(m);
                for (size_t t = 0; t < NTARGETS; t++) {
                    if (!g_targets[t].found &&
                        fp == (void *)((BYTE *)ga + g_targets[t].rva)) {
                        g_targets[t].found = 1;
                        const char *mname = "?";
                        int nargs = -1;
                        __try { mname = api_method_get_name(m); } __except (EXCEPTION_EXECUTE_HANDLER) {}
                        __try { nargs = api_method_get_param_count(m); } __except (EXCEPTION_EXECUTE_HANDLER) {}
                        logf("HIT[%s] rva=0x%llX class[%zu]=%s.%s method[%zu]=%s params=%d ptr=%p",
                             g_targets[t].tag, g_targets[t].rva, c, cns, cname, mi, mname, nargs, fp);
                    }
                }
                mi++;
            }
        }
    }

    logf("enumeration done in %llu ms: classes=%zu methods=%zu",
         GetTickCount64() - t0, totalClasses, totalMethods);

    /* 5) 判定 */
    int hits = 0;
    for (size_t t = 0; t < NTARGETS; t++) {
        logf("verdict[%s] rva=0x%llX -> %s", g_targets[t].tag, g_targets[t].rva,
             g_targets[t].found ? "FOUND" : "MISS");
        hits += g_targets[t].found;
    }
    logf("VERDICT: %d/%d", hits, (int)NTARGETS);
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
