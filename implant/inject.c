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
#include <stdio.h>

int wmain(int argc, wchar_t **argv) {
    if (argc < 3) {
        wprintf(L"usage: inject.exe <pid> <dll-path>\n");
        return 1;
    }
    DWORD pid = (DWORD)_wtoi(argv[1]);
    const wchar_t *dllPath = argv[2];

    /* 转为 ANSI 供 LoadLibraryA */
    char dllA[MAX_PATH];
    WideCharToMultiByte(CP_ACP, 0, dllPath, -1, dllA, MAX_PATH, NULL, NULL);

    HANDLE hProc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (!hProc) { wprintf(L"OpenProcess failed err=%lu (pid=%lu)\n", GetLastError(), pid); return 2; }
    wprintf(L"opened pid=%lu\n", pid);

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
