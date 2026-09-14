/* hooktest.c — detour 引擎离线单元验证（不接触游戏）
 * 目标：手汇编一个与 SetVelocity 完全同构的函数（14B 序言 + RIP 相对读 + 混淆 imm8 + ret），
 *       用 implant.c 同一套 install_detour 代码路径挂钩，验证：
 *       1) 序言校验通过  2) 钩子命中  3) 原行为经 trampoline 完整保留（含 RIP disp32 重定位正确）
 */
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>

typedef void (*fn2)(void *, void *);
static volatile LONG g_hits = 0;
static fn2 g_tramp = NULL;
static void * __fastcall hook(void *self, void *val) {
    InterlockedIncrement(&g_hits);
    g_tramp(self, val);
    return NULL;
}

/* ---- 与 implant.c 相同的引擎（复制，测试即验证该实现） ---- */
static void *alloc_near(void *target, SIZE_T size) {
    BYTE *t = (BYTE *)target;
    BYTE *lo = (BYTE *)(((DWORD64)t - 0x40000000) & ~0xFFFFull);
    BYTE *hi = (BYTE *)(((DWORD64)t + 0x40000000) & ~0xFFFFull);
    for (BYTE *a = lo; a + size < hi; a += 0x10000) {
        void *p = VirtualAlloc(a, size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
        if (p == a) return p;
        if (p) VirtualFree(p, 0, MEM_RELEASE);
    }
    return NULL;
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
static int install_detour(void *target, void *hookfn, fn2 *trampOut) {
    BYTE *t = (BYTE *)target;
    if (!(t[0]==0x48 && t[1]==0x89 && (t[2]&0xC7)==0x81 &&
          t[7]==0x0F && t[8]==0xB6 && (t[9]&0xC7)==0x05)) {
        printf("prologue check FAILED: %02X %02X %02X / %02X %02X %02X\n",
               t[0],t[1],t[2],t[7],t[8],t[9]);
        return 0;
    }
    if (!mask_match(t, "48 89 91 F8 00 00 00 0F B6 05 ? ? ? ? 34")) {
        printf("sig check FAILED\n"); return 0;
    }
    DWORD old;
    if (!VirtualProtect(t, 14, PAGE_EXECUTE_READWRITE, &old)) return 0;
    void *tramp = alloc_near(t, 64);
    if (!tramp) { VirtualProtect(t, 14, old, &old); return 0; }
    memcpy(tramp, t, 14);
    *(DWORD *)((BYTE *)tramp + 10) += (DWORD)((t + 14) - ((BYTE *)tramp + 14));
    BYTE back[] = { 0xFF, 0x25, 0, 0, 0, 0 };
    memcpy((BYTE *)tramp + 14, back, 6);
    *(DWORD64 *)((BYTE *)tramp + 20) = (DWORD64)(t + 14);
    BYTE jmp[] = { 0xFF, 0x25, 0, 0, 0, 0 };
    memcpy(t, jmp, 6);
    *(DWORD64 *)(t + 6) = (DWORD64)hookfn;
    VirtualProtect(t, 14, old, &old);
    FlushInstructionCache(GetCurrentProcess(), t, 14);
    *trampOut = (fn2)tramp;
    return 1;
}

int main(void) {
    /* 布局：code(24B) | 填充 | data g_seed @ +0x80 */
    BYTE *mem = VirtualAlloc(NULL, 0x200, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    BYTE *code = mem;
    BYTE *seed = mem + 0x80;
    *seed = 0x77;

    /* mov [rcx+0F8], rdx          48 89 91 F8 00 00 00
       movzx eax, [rip+disp32]     0F B6 05 <disp>      (disp = seed-(code+14))
       xor al, 0xC4                34 C4                (模拟混淆 imm8)
       mov [rcx+0F4], al           88 81 F4 00 00 00
       ret                         C3 */
    int32_t disp = (int32_t)(seed - (code + 14));
    code[0]=0x48;code[1]=0x89;code[2]=0x91;code[3]=0xF8;code[4]=0;code[5]=0;code[6]=0;
    code[7]=0x0F;code[8]=0xB6;code[9]=0x05;
    memcpy(code+10, &disp, 4);
    code[14]=0x34;code[15]=0xC4;
    code[16]=0x88;code[17]=0x81;code[18]=0xF4;code[19]=0;code[20]=0;code[21]=0;
    code[22]=0xC3;

    BYTE obj[0x200] = {0};
    fn2 f = (fn2)code;

    /* 1) 基线调用 */
    f(obj, (void *)(DWORD64)0x1234);
    uint64_t v0 = *(uint64_t *)(obj + 0xF8);
    BYTE f0 = obj[0xF4];
    printf("baseline: f8=%llX f4=%02X (expect 1234/33)\n", (unsigned long long)v0, f0);
    if (v0 != 0x1234 || f0 != (0x77 ^ 0xC4)) { printf("BASELINE FAIL\n"); return 1; }

    /* 2) 挂钩 */
    if (!install_detour(code, (void *)hook, &g_tramp)) { printf("INSTALL FAIL\n"); return 2; }
    printf("install OK (tramp=%p)\n", (void *)g_tramp);

    /* 3) 再调用：钩子命中 + 行为保留（RIP 修正正确 -> f4 同值） */
    memset(obj, 0, sizeof(obj));
    f(obj, (void *)(DWORD64)0x9999);
    uint64_t v1 = *(uint64_t *)(obj + 0xF8);
    BYTE f1 = obj[0xF4];
    int pass = (g_hits == 1 && v1 == 0x9999 && f1 == f0);
    printf("hooked: hits=%ld f8=%llX f4=%02X -> %s\n",
           g_hits, (unsigned long long)v1, f1, pass ? "PASS" : "FAIL");
    return pass ? 0 : 3;
}
