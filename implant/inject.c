/* inject.c — POC 注入器：把 implant.dll 载入运行中的游戏进程
 *
 * 用法: inject.exe <pid> <dll绝对路径>
 * 方法: OpenProcess -> VirtualAllocEx -> WriteProcessMemory(路径)
 *       -> CreateRemoteThread(LoadLibraryA)
 * 说明: POC 阶段用最朴素的 LoadLibrary 注入（模块列表可见），
 *       仅用于验证 il2cpp 运行时解析；反检测注入手法是阶段 2 的事。
 */
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <aclapi.h>
#include <sddl.h>
#include <stdio.h>

static void enable_debug_priv(void) {
    HANDLE tok;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &tok)) {
        wprintf(L"priv: OpenProcessToken failed err=%lu\n", GetLastError()); return;
    }
    LUID luid;
    if (LookupPrivilegeValueW(NULL, L"SeDebugPrivilege", &luid)) {
        TOKEN_PRIVILEGES tp = { 1, { { luid, SE_PRIVILEGE_ENABLED } } };
        BOOL ok = AdjustTokenPrivileges(tok, FALSE, &tp, sizeof(tp), NULL, NULL);
        wprintf(L"priv: SeDebugPrivilege adjust=%d err=%lu\n", ok, GetLastError());
    } else wprintf(L"priv: LookupPrivilegeValue failed err=%lu\n", GetLastError());
    CloseHandle(tok);
}

/* 创建时注入：挂起启动游戏 -> 注入 -> 恢复（抢在反作弊初始化前） */
static int spawn_inject(const wchar_t *exe, const wchar_t *workdir, const char *dllA) {
    STARTUPINFOW si; PROCESS_INFORMATION pi;
    ZeroMemory(&si, sizeof(si)); si.cb = sizeof(si);
    ZeroMemory(&pi, sizeof(pi));
    wchar_t cmd[MAX_PATH * 2];
    wcscpy_s(cmd, MAX_PATH * 2, exe);
    if (!CreateProcessW(exe, cmd, NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, workdir, &si, &pi)) {
        wprintf(L"spawn: CreateProcess failed err=%lu\n", GetLastError()); return 7;
    }
    wprintf(L"spawn: pid=%lu suspended\n", pi.dwProcessId);

    size_t len = strlen(dllA) + 1;
    void *remote = VirtualAllocEx(pi.hProcess, NULL, len, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!remote) { wprintf(L"spawn: VirtualAllocEx failed err=%lu\n", GetLastError()); TerminateProcess(pi.hProcess, 1); return 3; }
    if (!WriteProcessMemory(pi.hProcess, remote, dllA, len, NULL)) {
        wprintf(L"spawn: WriteProcessMemory failed err=%lu\n", GetLastError()); TerminateProcess(pi.hProcess, 1); return 4;
    }
    HMODULE k32 = GetModuleHandleW(L"kernel32.dll");
    FARPROC loadLib = GetProcAddress(k32, "LoadLibraryA");
    HANDLE hThread = CreateRemoteThread(pi.hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)loadLib, remote, 0, NULL);
    if (!hThread) { wprintf(L"spawn: CreateRemoteThread failed err=%lu\n", GetLastError()); TerminateProcess(pi.hProcess, 1); return 5; }
    WaitForSingleObject(hThread, 15000);
    DWORD ec = 0; GetExitCodeThread(hThread, &ec);
    wprintf(L"spawn: LoadLibraryA module=%p (0=failed)\n", (void *)(DWORD64)ec);
    CloseHandle(hThread);

    ResumeThread(pi.hThread);
    wprintf(L"spawn: resumed\n");
    CloseHandle(pi.hThread); CloseHandle(pi.hProcess);
    return ec ? 0 : 6;
}

int wmain(int argc, wchar_t **argv) {
    /* --spawn <exe> <workdir> <dll> : 创建时注入 */
    if (argc >= 5 && wcscmp(argv[1], L"--spawn") == 0) {
        enable_debug_priv();
        char dllA[MAX_PATH];
        WideCharToMultiByte(CP_ACP, 0, argv[4], -1, dllA, MAX_PATH, NULL, NULL);
        return spawn_inject(argv[2], argv[3], dllA);
    }
    if (argc < 3) {
        wprintf(L"usage: inject.exe <pid> <dll-path>\n        inject.exe --spawn <exe> <workdir> <dll-path>\n");
        return 1;
    }
    DWORD pid = (DWORD)_wtoi(argv[1]);
    const wchar_t *dllPath = argv[2];

    enable_debug_priv();

    /* 转为 ANSI 供 LoadLibraryA */
    char dllA[MAX_PATH];
    WideCharToMultiByte(CP_ACP, 0, dllPath, -1, dllA, MAX_PATH, NULL, NULL);

    HANDLE hProc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (!hProc) { wprintf(L"OpenProcess(ALL) failed err=%lu, retry MAXIMUM_ALLOWED\n", GetLastError());
        hProc = OpenProcess(MAXIMUM_ALLOWED, FALSE, pid); }
    if (!hProc) { wprintf(L"OpenProcess failed err=%lu (pid=%lu)\n", GetLastError(), pid); return 2; }
    wprintf(L"opened pid=%lu\n", pid);

    /* 权限诊断：逐项探测 */
    {
        BYTE probe; SIZE_T got;
        BOOL r = ReadProcessMemory(hProc, (LPCVOID)0x1000, &probe, 1, &got);
        wprintf(L"diag: ReadProcessMemory=%d err=%lu\n", r, r ? 0 : GetLastError());
        void *t = VirtualAllocEx(hProc, NULL, 0x1000, MEM_RESERVE, PAGE_READWRITE);
        wprintf(L"diag: VirtualAllocEx(reserve)=%p err=%lu\n", t, t ? 0 : GetLastError());
        if (t) VirtualFreeEx(hProc, t, 0, MEM_RELEASE);
    }

    /* DACL 诊断：谁在拒绝 */
    {
        PSECURITY_DESCRIPTOR sd = NULL;
        DWORD rc = GetSecurityInfo(hProc, SE_KERNEL_OBJECT,
            DACL_SECURITY_INFORMATION | OWNER_SECURITY_INFORMATION, NULL, NULL,
            NULL, NULL, &sd);
        if (rc == ERROR_SUCCESS && sd) {
            BOOL daclPresent = FALSE, daclDefaulted = FALSE;
            PACL dacl = NULL;
            if (GetSecurityDescriptorDacl(sd, &daclPresent, &dacl, &daclDefaulted) && daclPresent && dacl) {
                ACL_SIZE_INFORMATION ai;
                GetAclInformation(dacl, &ai, sizeof(ai), AclSizeInformation);
                wprintf(L"diag: DACL aces=%lu\n", ai.AceCount);
                for (DWORD i = 0; i < ai.AceCount; i++) {
                    void *ace;
                    if (!GetAce(dacl, i, &ace)) continue;
                    ACE_HEADER *h = (ACE_HEADER *)ace;
                    if (h->AceType != ACCESS_ALLOWED_ACE_TYPE && h->AceType != ACCESS_DENIED_ACE_TYPE) continue;
                    ACCESS_ALLOWED_ACE *a = (ACCESS_ALLOWED_ACE *)ace;
                    SID *sid = (SID *)&a->SidStart;
                    wchar_t name[64] = L"?", dom[64] = L"?";
                    DWORD nl = 64, dl = 64; SID_NAME_USE use;
                    LookupAccountSidW(NULL, sid, name, &nl, dom, &dl, &use);
                    wprintf(L"  ace[%lu] %s mask=0x%08lX %s\\%s\n", i,
                        h->AceType == ACCESS_DENIED_ACE_TYPE ? L"DENY" : L"ALLOW",
                        a->Mask, dom, name);
                }
            } else wprintf(L"diag: no DACL\n");
            LocalFree(sd);
        } else wprintf(L"diag: GetSecurityInfo err=%lu\n", rc);
    }

    size_t len = strlen(dllA) + 1;
    void *remote = VirtualAllocEx(hProc, NULL, len, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!remote) { wprintf(L"VirtualAllocEx failed err=%lu\n", GetLastError()); return 3; }

    if (!WriteProcessMemory(hProc, remote, dllA, len, NULL)) {
        wprintf(L"WriteProcessMemory failed err=%lu\n", GetLastError()); return 4;
    }
    wprintf(L"wrote path at %p\n", remote);

    HMODULE k32 = GetModuleHandleW(L"kernel32.dll");
    FARPROC loadLib = GetProcAddress(k32, "LoadLibraryA");

    HANDLE hThread = CreateRemoteThread(hProc, NULL, 0,
        (LPTHREAD_START_ROUTINE)loadLib, remote, 0, NULL);
    if (!hThread) { wprintf(L"CreateRemoteThread failed err=%lu\n", GetLastError()); return 5; }

    WaitForSingleObject(hThread, 15000);
    DWORD exitCode = 0;
    GetExitCodeThread(hThread, &exitCode);
    wprintf(L"LoadLibraryA returned module=%p (0=failed)\n", (void *)(DWORD64)exitCode);

    CloseHandle(hThread);
    VirtualFreeEx(hProc, remote, 0, MEM_RELEASE);
    CloseHandle(hProc);
    return exitCode ? 0 : 6;
}
