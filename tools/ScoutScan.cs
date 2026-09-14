// ScoutScan.cs - reconnaissance scanner: locate the injected DLL inside the game process
// WITHOUT assuming the DLL image is its own allocation. Reads every MEM_PRIVATE committed
// readable region (in <=1MB chunks) and searches three anchors:
//   A) embedded SHA-256 block "f381d853..." (image offset 0x183FC0)
//   B) ASCII "GameAssembly.dll" (image offset 0x183FA0)
//   C) ASCII "skill-manager-clean" (build id string)
// Outputs the allocation base, the offset of each hit (=> candidate DLL base = hit - offset),
// plus a summary of private allocations first seen.
//
// Build: csc /nologo /out:ScoutScan.exe ScoutScan.cs
// Run (admin): ScoutScan.exe                   (waits for Maplestory_Classic.exe, scans until found)
//              ScoutScan.exe --once <pid>      (scan a single already-running pid)
//              ScoutScan.exe <procname> --duration N (scan for N seconds, default 120)
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Globalization;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;

internal static class ScoutScan
{
    private const uint PROCESS_QUERY_INFORMATION = 0x0400;
    private const uint PROCESS_VM_READ = 0x0010;
    private const uint MEM_COMMIT = 0x1000;
    private const uint MEM_PRIVATE = 0x20000;
    private const uint PAGE_NOACCESS = 0x01;
    private const uint PAGE_GUARD = 0x100;

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
    [DllImport("kernel32.dll")]
    private static extern IntPtr VirtualQueryEx(IntPtr process, IntPtr address, out MEMORY_BASIC_INFORMATION buffer, IntPtr length);
    [DllImport("kernel32.dll")]
    private static extern bool CloseHandle(IntPtr handle);

    private static readonly byte[] AnchorA = Encoding.ASCII.GetBytes("f381d85319e8c64d8798206550df077da8f750b3313a063737fa587dd0c2d80");
    private const long OffA = 0x183FC0;
    private static readonly byte[] AnchorB = Encoding.ASCII.GetBytes("GameAssembly.dll");
    private const long OffB = 0x183FA0;
    private static readonly byte[] AnchorC = Encoding.ASCII.GetBytes("skill-manager-clean");
    private const long OffC = 0x0;

    private static void Log(string s) { Console.WriteLine("[{0:HH:mm:ss.fff}] {1}", DateTime.Now, s); }

    private static void ScanOne(string tag, IntPtr h, long regionBase, long regionSize, List<string> report)
    {
        const int CHUNK = 0x100000; // 1MB
        long pos = 0;
        byte[] buf = new byte[CHUNK];
        while (pos < regionSize)
        {
            int want = (int)Math.Min(CHUNK, regionSize - pos);
            IntPtr rd;
            if (!ReadProcessMemory(h, new IntPtr(regionBase + pos), buf, new IntPtr(want), out rd) || rd.ToInt64() < want)
                return; // unreadable part
            byte[] data = buf; int len = want;
            int iA = IndexOf(data, len, AnchorA);
            if (iA >= 0)
                report.Add(string.Format("{0}: SHA-256 block @ {1:X} -> DLL base candidate {2:X}", tag, regionBase + pos + iA, regionBase + pos + iA - OffA));
            int iB = IndexOf(data, len, AnchorB);
            if (iB >= 0)
                report.Add(string.Format("{0}: GameAssembly.dll string @ {1:X} -> base candidate {2:X}", tag, regionBase + pos + iB, regionBase + pos + iB - OffB));
            int iC = IndexOf(data, len, AnchorC);
            if (iC >= 0)
                report.Add(string.Format("{0}: skill-manager-clean @ {1:X}", tag, regionBase + pos + iC));
            pos += CHUNK;
        }
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

    public static int Main(string[] args)
    {
        string procName = "Maplestory_Classic";
        int durationSec = 120;
        int oncePid = 0;
        for (int i = 0; i < args.Length; i++)
        {
            if (args[i] == "--once" && i + 1 < args.Length) oncePid = int.Parse(args[++i], CultureInfo.InvariantCulture);
            else if (args[i] == "--duration" && i + 1 < args.Length) durationSec = int.Parse(args[++i], CultureInfo.InvariantCulture);
            else if (!args[i].StartsWith("--")) procName = args[i];
        }

        if (oncePid == 0)
        {
            Log("waiting for process " + procName + " (start injection via ControlProc)...");
            DateTime dl = DateTime.Now.AddSeconds(durationSec);
            int pid = -1;
            while (DateTime.Now < dl)
            {
                Process[] ps = Process.GetProcessesByName(procName.EndsWith(".exe", StringComparison.OrdinalIgnoreCase) ? procName.Substring(0, procName.Length - 4) : procName);
                if (ps.Length > 0) { pid = ps[0].Id; break; }
                Thread.Sleep(300);
            }
            if (pid < 0) { Log("process never appeared."); return 2; }
            Log("pid=" + pid + " - scanning for anchors...");
            oncePid = pid;
        }

        IntPtr h = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, false, oncePid);
        if (h == IntPtr.Zero) { Log("ERROR: OpenProcess failed (admin?)."); return 3; }

        List<string> report = new List<string>();
        int allocCount = 0;
        long addr = 0;
        MEMORY_BASIC_INFORMATION mbi;
        int mbiSize = Marshal.SizeOf(typeof(MEMORY_BASIC_INFORMATION));
        DateTime scanDeadline = DateTime.Now.AddSeconds(durationSec);
        bool done = false;
        while (DateTime.Now < scanDeadline && !done)
        {
            report.Clear();
            addr = 0; allocCount = 0;
            var allocs = new List<Tuple<long, long, uint>>();
            while (VirtualQueryEx(h, new IntPtr(addr), out mbi, new IntPtr(mbiSize)) != IntPtr.Zero)
            {
                long rb = mbi.BaseAddress.ToInt64();
                long rs = (long)mbi.RegionSize.ToUInt64();
                if (mbi.State == MEM_COMMIT && mbi.Type == MEM_PRIVATE
                    && (mbi.Protect & (PAGE_NOACCESS | PAGE_GUARD)) == 0)
                {
                    ScanOne("alloc", h, rb, rs, report);
                    // remember the first few allocation starts for summary
                    if (rb == mbi.AllocationBase.ToInt64())
                    {
                        allocCount++;
                        if (allocs.Count < 8) allocs.Add(new Tuple<long, long, uint>(rb, rs, mbi.Protect));
                    }
                }
                long next = rb + rs;
                if (next <= addr) break;
                addr = next;
            }
            if (report.Count > 0)
            {
                Log("FOUND (" + report.Count + " anchor hit sets)");
                foreach (string r in report) Log("  " + r);
                done = true;
                break;
            }
            Thread.Sleep(100);
        }
        if (!done)
        {
            Log("timeout: no anchors found after " + durationSec + "s");
            Log("private allocation snapshot (allocation starts):");
            addr = 0;
            while (VirtualQueryEx(h, new IntPtr(addr), out mbi, new IntPtr(mbiSize)) != IntPtr.Zero)
            {
                long rb = mbi.BaseAddress.ToInt64();
                long rs = (long)mbi.RegionSize.ToUInt64();
                if (mbi.State == MEM_COMMIT && mbi.Type == MEM_PRIVATE && rb == mbi.AllocationBase.ToInt64())
                {
                    // only show plausible sizes
                    if (rs >= 0x100000 && rs <= 0x4000000)
                        Log("    base=0x" + rb.ToString("X", CultureInfo.InvariantCulture)
                            + " size=0x" + rs.ToString("X", CultureInfo.InvariantCulture)
                            + " protect=0x" + mbi.Protect.ToString("X8", CultureInfo.InvariantCulture));
                }
                long next = rb + rs;
                if (next <= addr) break;
                addr = next;
            }
        }
        CloseHandle(h);
        return done ? 0 : 1;
    }
}