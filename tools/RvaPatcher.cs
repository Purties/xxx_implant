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
// Detection is two-tier:
//   A) fast path: region-base signature check (region start == allocation base, sig at +0x183FC0)
//   B) fallback:  full content scan of every readable MEM_PRIVATE region (1MB chunks, overlap-safe)
//                 searching the SHA-256 anchor anywhere; DLL base = hit - 0x183FC0. This works no
//                 matter how the manual mapper laid the image out (offset-in-allocation, split
//                 per-section protection, late copy-in).
// A logfile is ALWAYS written (patcher_run_<timestamp>.log next to the exe) unless --no-logfile,
// so a failed run leaves evidence instead of a vanished console window.
//
// Build: C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe /nologo /out:RvaPatcher.exe RvaPatcher.cs
// Usage (admin):  RvaPatcher.exe                      -> wait for Maplestory_Classic.exe, patch, watch 20s
//                 RvaPatcher.exe MapleStory --duration 30
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

    private static Action<string> Log = s => Console.WriteLine("[{0:HH:mm:ss.fff}] {1}", DateTime.Now, s);

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

    // enumerate candidate DLL bases: MEM_PRIVATE committed regions.
    // Manual-mapped image may be one big allocation (RXW whole) OR split by protection layout with a
    // small first region (< 8MB), so size filter is deliberately wide (1MB..16MB); the embedded
    // SHA-256 signature confirms with near-zero false positives.
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
                && regionSize >= 0x100000 && regionSize <= 0x4000000
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

    // diagnostic: dump the first few MEM_PRIVATE allocations (base/size/protect) so a missed
    // detection can be reasoned about instead of guessed.
    private static void DumpPrivateAllocs(IntPtr hProc, int max)
    {
        Log("  -- first private allocations (diag) --");
        int shown = 0;
        long addr = 0;
        MEMORY_BASIC_INFORMATION mbi;
        int mbiSize = Marshal.SizeOf(typeof(MEMORY_BASIC_INFORMATION));
        while (VirtualQueryEx(hProc, new IntPtr(addr), out mbi, new IntPtr(mbiSize)) != IntPtr.Zero && shown < max)
        {
            long regionBase = mbi.BaseAddress.ToInt64();
            long regionSize = (long)mbi.RegionSize.ToUInt64();
            if (mbi.State == MEM_COMMIT && mbi.Type == MEM_PRIVATE)
            {
                Log("    base=0x" + regionBase.ToString("X", CultureInfo.InvariantCulture)
                    + " size=0x" + regionSize.ToString("X", CultureInfo.InvariantCulture)
                    + " protect=0x" + mbi.Protect.ToString("X8", CultureInfo.InvariantCulture));
                shown++;
            }
            long next = regionBase + regionSize;
            if (next <= addr) break;
            addr = next;
        }
        if (shown == 0) Log("    (no private committed regions)");
    }

    private static int IndexOf(byte[] hay, int len, byte[] needle)
    {
        int last = len - needle.Length;
        if (last < 0) return -1;
        for (int i = 0; i <= last; i++)
        {
            if (hay[i] != needle[0]) continue;
            int j = 1;
            for (; j < needle.Length; j++) if (hay[i + j] != needle[j]) break;
            if (j == needle.Length) return i;
        }
        return -1;
    }

    // Fallback detection (tier B): full content scan of every readable MEM_PRIVATE region.
    // Does NOT assume the DLL image starts at an allocation base or occupies one region:
    // the signature anchor is searched anywhere; candidate DLL base = hit - SignatureOffset.
    // Candidates are validated by checking the first dispatch lea bytes at base+0x127CDB.
    // Chunk-boundary safe: the last (sigLen-1) bytes of each chunk are carried over.
    private static List<long> FindDllBasesContentScan(IntPtr hProc)
    {
        List<long> found = new List<long>();
        const int CHUNK = 0x100000; // 1MB
        int overlap = Signature.Length - 1;
        byte[] chunk = new byte[CHUNK];
        byte[] tail = new byte[overlap];
        byte[] window = new byte[CHUNK + overlap];
        long addr = 0;
        MEMORY_BASIC_INFORMATION mbi;
        int mbiSize = Marshal.SizeOf(typeof(MEMORY_BASIC_INFORMATION));
        long scanned = 0;
        while (VirtualQueryEx(hProc, new IntPtr(addr), out mbi, new IntPtr(mbiSize)) != IntPtr.Zero)
        {
            long regionBase = mbi.BaseAddress.ToInt64();
            long regionSize = (long)mbi.RegionSize.ToUInt64();
            if (mbi.State == MEM_COMMIT && mbi.Type == MEM_PRIVATE
                && (mbi.Protect & (PAGE_NOACCESS | PAGE_GUARD)) == 0)
            {
                long pos = 0;
                bool haveTail = false;
                while (pos < regionSize)
                {
                    int want = (int)Math.Min(CHUNK, regionSize - pos);
                    IntPtr rd;
                    if (!ReadProcessMemory(hProc, new IntPtr(regionBase + pos), chunk, new IntPtr(want), out rd) || rd.ToInt64() != want)
                    {
                        pos += want;
                        haveTail = false;
                        continue;
                    }
                    scanned += want;
                    // assemble search window: [tail][chunk]
                    int winLen;
                    long winStartAbs; // absolute address of window[0]
                    if (haveTail)
                    {
                        Array.Copy(tail, 0, window, 0, overlap);
                        Array.Copy(chunk, 0, window, overlap, want);
                        winLen = overlap + want;
                        winStartAbs = regionBase + pos - overlap;
                    }
                    else
                    {
                        Array.Copy(chunk, 0, window, 0, want);
                        winLen = want;
                        winStartAbs = regionBase + pos;
                    }
                    int idx = IndexOf(window, winLen, Signature);
                    while (idx >= 0)
                    {
                        long hitAbs = winStartAbs + idx;
                        long candBase = hitAbs - SignatureOffset;
                        if (!found.Contains(candBase))
                        {
                            // validate: first dispatch lea bytes at candBase+0x127CDB
                            byte[] lea = new byte[3];
                            IntPtr lr;
                            bool valid = ReadProcessMemory(hProc, new IntPtr(candBase + 0x127CDB), lea, new IntPtr(3), out lr)
                                         && lr.ToInt64() == 3 && lea[0] == 0x48 && lea[1] == 0x8D && lea[2] == 0x83;
                            Log("  content-scan: signature hit at 0x" + hitAbs.ToString("X", CultureInfo.InvariantCulture)
                                + " -> candidate DLL base 0x" + candBase.ToString("X", CultureInfo.InvariantCulture)
                                + (valid ? " (lea check OK)" : " (lea check FAILED - stray copy?)"));
                            if (valid) found.Add(candBase);
                        }
                        idx = IndexOfAt(window, winLen, Signature, idx + 1);
                    }
                    // carry over the last `overlap` bytes of this chunk
                    int tailLen = Math.Min(overlap, want);
                    Array.Copy(chunk, want - tailLen, tail, overlap - tailLen, tailLen);
                    if (tailLen < overlap) Array.Clear(tail, 0, overlap - tailLen);
                    haveTail = true;
                    pos += want;
                }
            }
            long next = regionBase + regionSize;
            if (next <= addr) break;
            addr = next;
        }
        Log("  content-scan done: scanned 0x" + scanned.ToString("X", CultureInfo.InvariantCulture) + " bytes of private memory");
        return found;
    }

    private static int IndexOfAt(byte[] hay, int len, byte[] needle, int start)
    {
        int last = len - needle.Length;
        for (int i = start; i <= last; i++)
        {
            if (hay[i] != needle[0]) continue;
            int j = 1;
            for (; j < needle.Length; j++) if (hay[i + j] != needle[j]) break;
            if (j == needle.Length) return i;
        }
        return -1;
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
        if (ok)
        {
            // read-back verification
            byte[] chk = new byte[4];
            IntPtr r;
            ok = ReadProcessMemory(hProc, new IntPtr(addr), chk, new IntPtr(4), out r) && r.ToInt64() == 4
                 && BitConverter.ToInt32(chk, 0) == s.NewDisp;
        }
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
        // persistent logfile so the patch trail survives console close.
        // ALWAYS on by default (patcher_run_<timestamp>.log next to the exe); --no-logfile disables.
        string logfile = null;
        System.IO.StreamWriter logWriter = null;
        string procName = "Maplestory_Classic";
        int durationSec = 20, intervalMs = 20, waitSec = 180;
        bool verifyOnly = false;
        bool noLogfile = false;
        List<string> positional = new List<string>();
        for (int i = 0; i < args.Length; i++)
        {
            if (args[i] == "--duration" && i + 1 < args.Length) durationSec = int.Parse(args[++i], CultureInfo.InvariantCulture);
            else if (args[i] == "--interval" && i + 1 < args.Length) intervalMs = int.Parse(args[++i], CultureInfo.InvariantCulture);
            else if (args[i] == "--wait" && i + 1 < args.Length) waitSec = int.Parse(args[++i], CultureInfo.InvariantCulture);
            else if (args[i] == "--logfile" && i + 1 < args.Length) logfile = args[++i];
            else if (args[i] == "--no-logfile") noLogfile = true;
            else if (args[i] == "--verify-only") verifyOnly = true;
            else if (!args[i].StartsWith("--")) positional.Add(args[i]);
        }
        if (positional.Count > 0) procName = positional[0];
        if (!noLogfile && logfile == null)
        {
            try
            {
                string exeDir = System.IO.Path.GetDirectoryName(System.Reflection.Assembly.GetExecutingAssembly().Location);
                logfile = System.IO.Path.Combine(exeDir, "patcher_run_" + DateTime.Now.ToString("yyyyMMdd_HHmmss") + ".log");
            }
            catch { /* fall back to console-only */ }
        }
        if (logfile != null)
        {
            try
            {
                logWriter = new System.IO.StreamWriter(logfile, true, Encoding.UTF8);
                logWriter.AutoFlush = true;
            }
            catch { logWriter = null; }
        }
        if (logWriter != null)
        {
            System.IO.StreamWriter lw = logWriter;
            Log = s => { Console.WriteLine("[{0:HH:mm:ss.fff}] {1}", DateTime.Now, s); lw.WriteLine("[{0:HH:mm:ss.fff}] {1}", DateTime.Now, s); };
            Log("==== RvaPatcher session start ====");
            Log("logfile: " + logfile);
        }

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
        if (pid < 0)
        {
            Log("ERROR: process never appeared.");
            if (logWriter != null) logWriter.Close();
            return 2;
        }
        Log("process pid=" + pid + " - watching for injected DLL...");

        IntPtr hProc = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION, false, pid);
        if (hProc == IntPtr.Zero)
        {
            Log("ERROR: OpenProcess failed (run as administrator).");
            if (logWriter != null) logWriter.Close();
            return 3;
        }

        HashSet<long> checkedRegions = new HashSet<long>();
        List<long> bases = new List<long>();
        DateTime procSeenAt = DateTime.Now;      // when the game process first appeared
        DateTime lastContentScan = DateTime.MinValue;
        while (DateTime.Now < waitDeadline && bases.Count == 0)
        {
            // tier A: fast region-base signature check (cheap, every poll)
            bases = FindDllBases(hProc, checkedRegions);
            if (bases.Count > 0) { Log("detection: fast path (region-base signature) hit"); break; }

            // tier B: full content scan fallback. Triggered once the process has been alive long
            // enough for the injection to have landed (~3s: hooks install at ~2.7s), then retried
            // every 3s. This catches images mapped at an offset inside a larger allocation or with
            // per-section protection, which the fast path's regionBase==AllocationBase test misses.
            double aliveSec = (DateTime.Now - procSeenAt).TotalSeconds;
            if (aliveSec >= 3.0 && (DateTime.Now - lastContentScan).TotalSeconds >= 3.0)
            {
                lastContentScan = DateTime.Now;
                Log("detection: fast path empty after " + aliveSec.ToString("F1") + "s - running full content scan (tier B)...");
                bases = FindDllBasesContentScan(hProc);
                if (bases.Count > 0) { Log("detection: content scan hit"); break; }
            }
            Thread.Sleep(100);
        }
        if (bases.Count == 0)
        {
            Log("ERROR: injected DLL signature not found within wait window.");
            Log("running one final full content scan before giving up...");
            bases = FindDllBasesContentScan(hProc);
        }
        if (bases.Count == 0)
        {
            Log("ERROR: still not found after final content scan. The DLL was likely never injected");
            Log("       (ControlProc injection not started / failed), OR it lives in non-private memory.");
            DumpPrivateAllocs(hProc, 12);
            CloseHandle(hProc);
            if (logWriter != null) logWriter.Close();
            return 4;
        }
        foreach (long b in bases)
        {
            byte[] mz = new byte[2];
            IntPtr mzRead;
            long sizeOfImage = 0;
            if (ReadProcessMemory(hProc, new IntPtr(b), mz, new IntPtr(2), out mzRead) && mzRead.ToInt64() == 2 && mz[0] == (byte)'M' && mz[1] == (byte)'Z')
            {
                byte[] e_lfanew = new byte[4];
                IntPtr r2;
                if (ReadProcessMemory(hProc, new IntPtr(b + 0x3C), e_lfanew, new IntPtr(4), out r2) && r2.ToInt64() == 4)
                {
                    uint peOff = BitConverter.ToUInt32(e_lfanew, 0);
                    byte[] opt = new byte[8];
                    IntPtr r3;
                    if (ReadProcessMemory(hProc, new IntPtr(b + peOff + 0x18 + 0x38), opt, new IntPtr(8), out r3) && r3.ToInt64() == 8)
                        sizeOfImage = BitConverter.ToUInt32(opt, 0);
                }
            }
            Log("DLL image base: 0x" + b.ToString("X", CultureInfo.InvariantCulture)
                + (mzRead.ToInt64() == 2 && mz[0] == (byte)'M' ? " (MZ ok, SizeOfImage=0x" + sizeOfImage.ToString("X", CultureInfo.InvariantCulture) + ")" : " (NO-MZ! suspicious)"));
        }

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
        if (logWriter != null) logWriter.Close();
        return 0;
    }
}
