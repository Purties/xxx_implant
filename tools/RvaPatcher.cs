// RvaPatcher.cs - live-patch the injected DLL's dispatch RVA table inside the game process.
// Field tool for ControlProc/MapleStory injection RVA migration (see UNPACKING_REPORT.md r5).
//
// The injected DLL (manual-mapped, build 2026-07-18) falls back to baked 0902 hook RVAs on the
// unrecognized 2026-09-13 client -> hooks land on wrong functions -> 0xc0000005 at +0xbbf663.
// This tool detects the injected DLL image in the game process by its embedded SHA-256
// hash-block (at image offset 0x183FC0) and rewrites the 5 critical dispatch
// `lea rax,[rbx+disp32]` immediates to the newly-resolved RVAs, repeatedly, so hook install
// (which lazily reads the dispatch at ~2.5s) picks up the corrected values.
//
// Build: C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe /nologo /out:RvaPatcher.exe RvaPatcher.cs
// Usage (admin):  RvaPatcher.exe                      -> wait for Maplestory_Classic.exe, patch, watch 15s
//                 RvaPatcher.exe MapleStory --duration 20
//                 RvaPatcher.exe --verify-only        -> report current disp32 values, no writes
// Workflow: run this FIRST, then start the game/injection via ControlProc as usual.
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Globalization;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;

internal static class RvaPatcher
{
    private const uint PROCESS_QUERY_INFORMATION = 0x0400;
    private const uint PROCESS_VM_READ = 0x0010;
    private const uint PROCESS_VM_WRITE = 0x0020;
    private const uint PROCESS_VM_OPERATION = 0x0008;
    private const uint MEM_COMMIT = 0x1000;
    private const uint MEM_PRIVATE = 0x20000;
    private const uint PAGE_NOACCESS = 0x01;
    private const uint PAGE_GUARD = 0x100;
    private const uint PAGE_EXECUTE_READWRITE = 0x40;

    [StructLayout(LayoutKind.Sequential)]
    private struct MEMORY_BASIC_INFORMATION
    {
        public IntPtr BaseAddress;
        public IntPtr AllocationBase;
        public uint AllocationProtect;
        public UIntPtr RegionSize;
        public uint State;
        public uint Protect;
        public uint Type;
    }

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr OpenProcess(uint access, bool inheritHandle, int processId);
    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool ReadProcessMemory(IntPtr process, IntPtr baseAddress, byte[] buffer, IntPtr size, out IntPtr bytesRead);
    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool WriteProcessMemory(IntPtr process, IntPtr baseAddress, byte[] buffer, IntPtr size, out IntPtr bytesWritten);
    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool VirtualProtectEx(IntPtr process, IntPtr address, UIntPtr size, uint newProtect, out uint oldProtect);
    [DllImport("kernel32.dll")]
    private static extern IntPtr VirtualQueryEx(IntPtr process, IntPtr address, out MEMORY_BASIC_INFORMATION buffer, IntPtr length);
    [DllImport("kernel32.dll")]
    private static extern bool CloseHandle(IntPtr handle);

    // first embedded SHA-256 (ASCII) at image offset 0x183FC0
    private static readonly byte[] Signature = Encoding.ASCII.GetBytes("f381d85319e8c64d8798206550df077da8f750b3313a063737fa587dd0c2d80");
    private const long SignatureOffset = 0x183FC0;

    private sealed class Site
    {
        public string Hook; public long Offset; public int OldDisp; public int NewDisp; public long SlotOffset;
        public Site(string h, long off, int o, int n, long slot) { Hook = h; Offset = off; OldDisp = o; NewDisp = n; SlotOffset = slot; }
    }

    private static readonly Site[] Sites = new Site[]
    {
        new Site("SetImpactNext", 0x127CDB, 0x011BE670, 0x01214940, 0xBE1920),
        new Site("SetVelocity",   0x127D07, 0x011BE640, 0x012144F0, 0xBE1938),
        new Site("DoCombatStep",  0x127D33, 0x011BEF10, 0x01215270, 0xBE1950),
        new Site("InputUpdate",   0x127DD5, 0x01660650, 0x014DB0B0, 0xBE1AA8),
        new Site("SetDamaged",    0x12800A, 0x01049B70, 0x010D74B0, 0xBE1C00),
    };

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr CreateToolhelp32Snapshot(uint flags, uint processId);
    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool Module32First(IntPtr snapshot, ref MODULEENTRY32 entry);
    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool Module32Next(IntPtr snapshot, ref MODULEENTRY32 entry);
    private const uint TH32CS_SNAPMODULE = 0x08;
    private const uint TH32CS_SNAPMODULE32 = 0x10;

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Ansi)]
    private struct MODULEENTRY32
    {
        public uint dwSize;
        public uint th32ModuleID;
        public uint th32ProcessID;
        public uint GlblcntUsage;
        public uint ProccntUsage;
        public IntPtr modBaseAddr;
        public uint modBaseSize;
        public IntPtr hModule;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 256)]
        public string szModule;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 260)]
        public string szExePath;
    }

    private static long GetModuleBase(int pid, string moduleName)
    {
        IntPtr snap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, (uint)pid);
        if (snap == new IntPtr(-1)) return 0;
        MODULEENTRY32 me = new MODULEENTRY32();
        me.dwSize = (uint)Marshal.SizeOf(typeof(MODULEENTRY32));
        long result = 0;
        if (Module32First(snap, ref me))
        {
            do
            {
                if (string.Equals(me.szModule, moduleName, StringComparison.OrdinalIgnoreCase))
                {
                    result = me.modBaseAddr.ToInt64();
                    break;
                }
            } while (Module32Next(snap, ref me));
        }
        CloseHandle(snap);
        return result;
    }

    private static void Log(string msg) { Console.WriteLine("[{0:HH:mm:ss.fff}] {1}", DateTime.Now, msg); }

    private static int FindProcess(string name)
    {
        string n = name.EndsWith(".exe", StringComparison.OrdinalIgnoreCase) ? name.Substring(0, name.Length - 4) : name;
        Process[] procs = Process.GetProcessesByName(n);
        if (procs.Length == 0) return -1;
        foreach (Process p in procs) if (p.MainWindowHandle != IntPtr.Zero) return p.Id;
        return procs[0].Id;
    }

    // test a single candidate region: does regionBase+0x183FC0 hold the signature?
    private static bool RegionHasSignature(IntPtr hProc, long regionBase)
    {
        byte[] buf = new byte[Signature.Length];
        IntPtr read;
        if (!ReadProcessMemory(hProc, new IntPtr(regionBase + SignatureOffset), buf, new IntPtr(buf.Length), out read))
            return false;
        if (read.ToInt64() != buf.Length) return false;
        for (int i = 0; i < buf.Length; i++) if (buf[i] != Signature[i]) return false;
        return true;
    }

    // enumerate candidate DLL bases: MEM_PRIVATE committed regions sized like the image (~8-16MB).
    // alreadyChecked only caches CONFIRMED hits; unconfirmed regions are re-tested every poll
    // (the DLL image may be mapped before its data/signature is fully copied in).
    private static List<long> FindDllBases(IntPtr hProc, HashSet<long> confirmed)
    {
        List<long> found = new List<long>();
        long addr = 0;
        MEMORY_BASIC_INFORMATION mbi;
        int mbiSize = Marshal.SizeOf(typeof(MEMORY_BASIC_INFORMATION));
        while (VirtualQueryEx(hProc, new IntPtr(addr), out mbi, new IntPtr(mbiSize)) != IntPtr.Zero)
        {
            long regionBase = mbi.BaseAddress.ToInt64();
            long regionSize = (long)mbi.RegionSize.ToUInt64();
            if (mbi.State == MEM_COMMIT && mbi.Type == MEM_PRIVATE
                && (mbi.Protect & (PAGE_NOACCESS | PAGE_GUARD)) == 0
                && regionSize >= 0x800000 && regionSize <= 0x1800000
                && regionBase == mbi.AllocationBase.ToInt64())     // region start == image base
            {
                if (confirmed.Contains(regionBase) || RegionHasSignature(hProc, regionBase))
                {
                    if (!found.Contains(regionBase)) found.Add(regionBase);
                    confirmed.Add(regionBase);
                }
            }
            long next = regionBase + regionSize;
            if (next <= addr) break;
            addr = next;
        }
        return found;
    }

    private static bool ReadSite(IntPtr hProc, long dllBase, Site s, out int curDisp)
    {
        curDisp = 0;
        byte[] buf = new byte[7];
        IntPtr read;
        if (!ReadProcessMemory(hProc, new IntPtr(dllBase + s.Offset), buf, new IntPtr(7), out read) || read.ToInt64() != 7)
            return false;
        if (buf[0] != 0x48 || buf[1] != 0x8D || buf[2] != 0x83)
            return false;
        curDisp = BitConverter.ToInt32(buf, 3);
        return true;
    }

    private static bool PatchSite(IntPtr hProc, long dllBase, Site s)
    {
        long addr = dllBase + s.Offset + 3;
        byte[] bytes = BitConverter.GetBytes(s.NewDisp);
        uint oldProt;
        if (!VirtualProtectEx(hProc, new IntPtr(dllBase + s.Offset), new UIntPtr(7), PAGE_EXECUTE_READWRITE, out oldProt))
            return false;
        IntPtr written;
        bool ok = WriteProcessMemory(hProc, new IntPtr(addr), bytes, new IntPtr(4), out written) && written.ToInt64() == 4;
        uint tmp;
        VirtualProtectEx(hProc, new IntPtr(dllBase + s.Offset), new UIntPtr(7), oldProt, out tmp);
        return ok;
    }

    // Eager-resolution path: the hook slot already holds (GameAssemblyBase + oldRVA).
    // Rewrite it to (GameAssemblyBase + newRVA). Returns 0=not-populated, 1=patched, 2=already-new, -1=mismatch.
    private static int PatchSlot(IntPtr hProc, long dllBase, Site s, long gaBase, out long curVal)
    {
        curVal = 0;
        long slotAddr = dllBase + s.SlotOffset;
        byte[] buf = new byte[8];
        IntPtr read;
        if (!ReadProcessMemory(hProc, new IntPtr(slotAddr), buf, new IntPtr(8), out read) || read.ToInt64() != 8)
            return 0;
        long val = BitConverter.ToInt64(buf, 0);
        curVal = val;
        if (val == 0) return 0;
        long newVal = gaBase + (uint)s.NewDisp;
        if (val == newVal) return 2;
        long oldVal = gaBase + (uint)s.OldDisp;
        if (val != oldVal)
        {
            // could be a slot populated from a different base or garbage; only patch if it looks like base+oldRVA
            return -1;
        }
        byte[] bytes = BitConverter.GetBytes(newVal);
        uint oldProt;
        if (!VirtualProtectEx(hProc, new IntPtr(slotAddr), new UIntPtr(8), PAGE_EXECUTE_READWRITE, out oldProt))
            return -1;
        IntPtr written;
        bool ok = WriteProcessMemory(hProc, new IntPtr(slotAddr), bytes, new IntPtr(8), out written) && written.ToInt64() == 8;
        uint tmp;
        VirtualProtectEx(hProc, new IntPtr(slotAddr), new UIntPtr(8), oldProt, out tmp);
        return ok ? 1 : -1;
    }

    public static int Main(string[] args)
    {
        string procName = "Maplestory_Classic";
        int durationSec = 15, intervalMs = 20, waitSec = 180;
        bool verifyOnly = false;
        List<string> positional = new List<string>();
        for (int i = 0; i < args.Length; i++)
        {
            if (args[i] == "--duration" && i + 1 < args.Length) durationSec = int.Parse(args[++i], CultureInfo.InvariantCulture);
            else if (args[i] == "--interval" && i + 1 < args.Length) intervalMs = int.Parse(args[++i], CultureInfo.InvariantCulture);
            else if (args[i] == "--wait" && i + 1 < args.Length) waitSec = int.Parse(args[++i], CultureInfo.InvariantCulture);
            else if (args[i] == "--verify-only") verifyOnly = true;
            else if (!args[i].StartsWith("--")) positional.Add(args[i]);
        }
        if (positional.Count > 0) procName = positional[0];

        Log("target=" + procName + " duration=" + durationSec + "s interval=" + intervalMs + "ms wait=" + waitSec + "s verifyOnly=" + verifyOnly);
        Log("waiting for process (start the game via ControlProc now)...");
        int pid = -1;
        DateTime waitDeadline = DateTime.Now.AddSeconds(waitSec);
        while (DateTime.Now < waitDeadline)
        {
            pid = FindProcess(procName);
            if (pid > 0) break;
            Thread.Sleep(500);
        }
        if (pid < 0) { Log("ERROR: process never appeared."); return 2; }
        Log("process pid=" + pid + " - watching for injected DLL...");

        IntPtr hProc = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION, false, pid);
        if (hProc == IntPtr.Zero) { Log("ERROR: OpenProcess failed (run as administrator)."); return 3; }

        HashSet<long> checkedRegions = new HashSet<long>();
        List<long> bases = new List<long>();
        while (DateTime.Now < waitDeadline && bases.Count == 0)
        {
            bases = FindDllBases(hProc, checkedRegions);
            if (bases.Count == 0) Thread.Sleep(100);
        }
        if (bases.Count == 0) { Log("ERROR: injected DLL signature not found within wait window."); CloseHandle(hProc); return 4; }
        foreach (long b in bases) Log("DLL image base: 0x" + b.ToString("X", CultureInfo.InvariantCulture));

        long gaBase = GetModuleBase(pid, "GameAssembly.dll");
        if (gaBase == 0) Log("WARN: GameAssembly.dll module base not found yet (slot path disabled until found)");
        else Log("GameAssembly.dll base: 0x" + gaBase.ToString("X", CultureInfo.InvariantCulture));

        DateTime deadline = DateTime.Now.AddSeconds(durationSec);
        int pass = 0;
        int patchCount = 0;
        while (DateTime.Now < deadline)
        {
            pass++;
            if (gaBase == 0 && pass % 10 == 0)  // retry module lookup occasionally
            {
                gaBase = GetModuleBase(pid, "GameAssembly.dll");
                if (gaBase != 0) Log("GameAssembly.dll base: 0x" + gaBase.ToString("X", CultureInfo.InvariantCulture));
            }
            foreach (long dllBase in bases)
            {
                foreach (Site s in Sites)
                {
                    int cur;
                    if (!ReadSite(hProc, dllBase, s, out cur))
                    {
                        if (pass == 1) Log("  " + s.Hook + ": site bytes unexpected at base 0x" + dllBase.ToString("X", CultureInfo.InvariantCulture) + " (skipped)");
                        break;
                    }
                    if (pass == 1)
                        Log("  " + s.Hook + " initial disp=0x" + cur.ToString("X", CultureInfo.InvariantCulture) + (cur == s.OldDisp ? " (matches old, will patch)" : cur == s.NewDisp ? " (already new)" : " (UNEXPECTED)"));
                    if (verifyOnly)
                    {
                        if (pass == 1)
                        {
                            byte[] sbuf = new byte[8];
                            IntPtr sread;
                            long sv = 0;
                            if (ReadProcessMemory(hProc, new IntPtr(dllBase + s.SlotOffset), sbuf, new IntPtr(8), out sread) && sread.ToInt64() == 8)
                                sv = BitConverter.ToInt64(sbuf, 0);
                            Log("    slot[" + s.Hook + "] = 0x" + sv.ToString("X", CultureInfo.InvariantCulture));
                        }
                        break;
                    }
                    if (cur != s.NewDisp)
                    {
                        if (PatchSite(hProc, dllBase, s))
                        {
                            patchCount++;
                            if (pass <= 3 || cur == s.OldDisp)
                                Log("  patched " + s.Hook + " lea: 0x" + cur.ToString("X", CultureInfo.InvariantCulture) + " -> 0x" + s.NewDisp.ToString("X", CultureInfo.InvariantCulture));
                        }
                        else Log("  WRITE FAILED for " + s.Hook + " lea");
                    }
                    // eager path: fix populated slot if it still holds base+oldRVA
                    if (gaBase != 0)
                    {
                        long sv;
                        int r = PatchSlot(hProc, dllBase, s, gaBase, out sv);
                        if (r == 1)
                        {
                            patchCount++;
                            Log("  patched " + s.Hook + " slot: 0x" + sv.ToString("X", CultureInfo.InvariantCulture) + " -> 0x" + (gaBase + (uint)s.NewDisp).ToString("X", CultureInfo.InvariantCulture));
                        }
                        else if (r == -1 && pass == 1)
                        {
                            Log("  " + s.Hook + " slot holds 0x" + sv.ToString("X", CultureInfo.InvariantCulture) + " (not base+oldRVA; left as-is)");
                        }
                    }
                }
            }
            if (verifyOnly) break;
            Thread.Sleep(intervalMs);
        }
        Log("done. passes=" + pass + " patchesApplied=" + patchCount);
        Log("verify in game dir hook_artifacts\\diagnostics: invincible-hook.log targets should be base+0x12144F0/+0x1214940/+0x1215270/+0x10D74B0; imgui-startup.log Update should install (rva=0x14DB0B0), no crash.");
        CloseHandle(hProc);
        return 0;
    }
}
