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
//                 searching lea anchors (48 8D 83 + known hook RVA disp) anywhere; DLL base =
//                 hit - site offset, confirmed by 5-site cross-verification (>=4/5).
// v6 (after round 5, 15:57): scan passes are SCAN-AND-PATCH - every old-RVA lea is rewritten on
// sight, every (GameAssemblyBase+oldRVA) qword cache is rewritten too. Plus PHASE 0: before the
// game even starts, the staged DLL image(s) inside ControlProc are patched, so the injected copy
// is born with new RVAs (round 5 proved the in-game resolver caches RVAs faster than we can win).
// A logfile is ALWAYS written (patcher_run_<timestamp>.log next to the exe) unless --no-logfile,
// so a failed run leaves evidence instead of a vanished console window.
//
// Build: C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe /nologo /out:RvaPatcher.exe RvaPatcher.cs
// Usage (admin):  RvaPatcher.exe                      -> phase0 + wait for Maplestory_Classic.exe, patch, watch 30s
//                 RvaPatcher.exe MapleStory --duration 40
//                 RvaPatcher.exe --verify-only        -> report current disp32 values, no writes
// Workflow: run this FIRST (ControlProc must already be running for phase0), then start injection.
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

    // Cross-verify a candidate DLL base: read all 5 dispatch lea sites at candBase+site.Offset,
    // count how many hold the expected opcode (48 8D 83) with disp == OldDisp or NewDisp.
    // A genuine mapped image passes 5/5 (or 4/5 if one site is mid-rewrite); a stray heap copy
    // of a fragment fails because the 5 sites won't line up at the correct relative offsets.
    private static int VerifyBase(IntPtr hProc, long candBase)
    {
        int ok = 0;
        foreach (Site s in Sites)
        {
            byte[] buf = new byte[7];
            IntPtr rd;
            if (!ReadProcessMemory(hProc, new IntPtr(candBase + s.Offset), buf, new IntPtr(7), out rd) || rd.ToInt64() != 7)
                continue;
            if (buf[0] != 0x48 || buf[1] != 0x8D || buf[2] != 0x83) continue;
            int disp = BitConverter.ToInt32(buf, 3);
            if (disp == s.OldDisp || disp == s.NewDisp) ok++;
        }
        return ok;
    }

    // Fallback detection (tier B): full content scan of every readable MEM_PRIVATE region.
    //
    // Anchor choice (r4, after the 2026-09-14 15:04 field run): the version-table SHA-256 block is
    // NOT a reliable anchor - the live image's hash region is wiped/hidden by the manual mapper and
    // only a stray, non-aligned heap copy survives (base derived from it failed the lea check).
    // The dispatch `lea rax,[rbx+disp32]` code, however, is provably intact & readable at detection
    // time (the DLL's own game-input probe read the baked old RVA 0x1660650 from it at +4.7s).
    //
    // v6 (after the 15:57 round-5 run): the scan is now a SCAN-AND-PATCH pass:
    //   1) lea hits holding an OLD disp are rewritten in place ON SIGHT (covers every copy of the
    //      dispatch - template/backup included - wherever it lives);
    //   2) qword hits holding (GameAssemblyBase + oldRVA) - i.e. already-resolved absolute hook
    //      pointers cached by the DLL's early resolver pass - are rewritten to (base + newRVA).
    //      Round 5 proved some hooks cache RVAs BEFORE our lea patch lands (probe still read the
    //      old RVA 0.8s after the patch; hooks installed 2-new/3-old), so the cache itself must
    //      be patched between the resolver pass and hook install (~+0.3s .. +1.9s window).
    // Candidate bases are still collected via 5-site cross-verification for the re-patch loop.
    // Chunk-boundary safe via an 8-byte carry-over tail.
    private static readonly byte[] LeaPrefix = new byte[] { 0x48, 0x8D, 0x83 };

    private static List<long> FindDllBasesContentScan(IntPtr hProc, long gaBase)
    {
        List<long> found = new List<long>();
        const int CHUNK = 0x100000; // 1MB
        const int OVERLAP = 8;      // >= 7 (full lea) so boundary-spanning leas are not missed
        byte[] chunk = new byte[CHUNK];
        byte[] tail = new byte[OVERLAP];
        byte[] window = new byte[CHUNK + OVERLAP];

        // map disp value -> site offsets that use it (old & new variants)
        var dispToOffsets = new Dictionary<int, List<long>>();
        foreach (Site s in Sites)
        {
            if (!dispToOffsets.ContainsKey(s.OldDisp)) dispToOffsets[s.OldDisp] = new List<long>();
            dispToOffsets[s.OldDisp].Add(s.Offset);
            if (!dispToOffsets.ContainsKey(s.NewDisp)) dispToOffsets[s.NewDisp] = new List<long>();
            dispToOffsets[s.NewDisp].Add(s.Offset);
        }

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
                    int winLen;
                    long winStartAbs;
                    if (haveTail)
                    {
                        Array.Copy(tail, 0, window, 0, OVERLAP);
                        Array.Copy(chunk, 0, window, OVERLAP, want);
                        winLen = OVERLAP + want;
                        winStartAbs = regionBase + pos - OVERLAP;
                    }
                    else
                    {
                        Array.Copy(chunk, 0, window, 0, want);
                        winLen = want;
                        winStartAbs = regionBase + pos;
                    }
                    int idx = IndexOf(window, winLen, LeaPrefix);
                    while (idx >= 0)
                    {
                        // need 7 bytes (3 opcode + 4 disp) from idx
                        if (idx + 7 <= winLen)
                        {
                            int disp = BitConverter.ToInt32(window, idx + 3);
                            List<long> offsets;
                            if (dispToOffsets.TryGetValue(disp, out offsets))
                            {
                                long hitAbs = winStartAbs + idx;
                                // v6 PATCH-ON-SIGHT: if this lea still holds an OLD disp, rewrite it
                                // to the corresponding NEW disp immediately - don't wait for base
                                // verification. Round 5 showed the resolver may read a copy we never
                                // verify as a "base"; patching every old-RVA lea in-place covers all
                                // copies (dispatch, template, backup) wherever they live.
                                foreach (Site s in Sites)
                                {
                                    if (disp == s.OldDisp && s.OldDisp != s.NewDisp)
                                    {
                                        byte[] newBytes = BitConverter.GetBytes(s.NewDisp);
                                        uint op;
                                        if (VirtualProtectEx(hProc, new IntPtr(hitAbs + 3), new UIntPtr(4), PAGE_EXECUTE_READWRITE, out op))
                                        {
                                            IntPtr wr;
                                            bool wok = WriteProcessMemory(hProc, new IntPtr(hitAbs + 3), newBytes, new IntPtr(4), out wr) && wr.ToInt64() == 4;
                                            uint tp;
                                            VirtualProtectEx(hProc, new IntPtr(hitAbs + 3), new UIntPtr(4), op, out tp);
                                            Log("  content-scan: PATCH-ON-SIGHT " + s.Hook + " lea @ 0x" + hitAbs.ToString("X", CultureInfo.InvariantCulture)
                                                + ": 0x" + s.OldDisp.ToString("X", CultureInfo.InvariantCulture) + " -> 0x" + s.NewDisp.ToString("X", CultureInfo.InvariantCulture)
                                                + (wok ? " (written)" : " (WRITE FAILED)"));
                                        }
                                        break;
                                    }
                                }
                                foreach (long siteOff in offsets)
                                {
                                    long candBase = hitAbs - siteOff;
                                    if (found.Contains(candBase)) continue;
                                    int matches = VerifyBase(hProc, candBase);
                                    Log("  content-scan: lea hit at 0x" + hitAbs.ToString("X", CultureInfo.InvariantCulture)
                                        + " disp=0x" + disp.ToString("X", CultureInfo.InvariantCulture)
                                        + " -> candidate base 0x" + candBase.ToString("X", CultureInfo.InvariantCulture)
                                        + " cross-verify " + matches + "/5"
                                        + (matches >= 4 ? " (ACCEPTED)" : " (rejected - stray fragment)"));
                                    if (matches >= 4)
                                    {
                                        found.Add(candBase);
                                        // v6: NO early return. Round 5 (15:57) proved the resolver does
                                        // not always read the copy we patch (probe read old RVA 0.8s
                                        // after patch; hooks installed 2-new/3-old split). There may be
                                        // a SECOND dispatch copy (template/backup) that we never saw
                                        // because v4/v5 returned on first hit. Scan everything, collect
                                        // every verified base, patch all of them.
                                        Log("  content-scan: verified base FOUND - continuing scan for more copies");
                                    }
                                }
                            }
                        }
                        idx = IndexOfAt(window, winLen, LeaPrefix, idx + 1);
                    }
                    // v6 qword cache patch: the DLL's resolver caches ABSOLUTE hook pointers
                    // (GameAssemblyBase + oldRVA) in heap slots before hook install. Round 5's
                    // 2-new/3-old split means some were cached before our lea patch. Find every
                    // 8-byte occurrence of (gaBase + oldRVA) and rewrite to (gaBase + newRVA).
                    if (gaBase != 0)
                    {
                        foreach (Site s in Sites)
                        {
                            long oldAbs = gaBase + (uint)s.OldDisp;
                            long newAbs = gaBase + (uint)s.NewDisp;
                            byte[] needle = BitConverter.GetBytes(oldAbs);
                            int q = IndexOf(window, winLen, needle);
                            while (q >= 0)
                            {
                                long qAbs = winStartAbs + q;
                                byte[] newBytes = BitConverter.GetBytes(newAbs);
                                uint op2;
                                if (VirtualProtectEx(hProc, new IntPtr(qAbs), new UIntPtr(8), PAGE_EXECUTE_READWRITE, out op2))
                                {
                                    IntPtr wr2;
                                    bool wok2 = WriteProcessMemory(hProc, new IntPtr(qAbs), newBytes, new IntPtr(8), out wr2) && wr2.ToInt64() == 8;
                                    uint tp2;
                                    VirtualProtectEx(hProc, new IntPtr(qAbs), new UIntPtr(8), op2, out tp2);
                                    Log("  content-scan: PATCH qword cache " + s.Hook + " @ 0x" + qAbs.ToString("X", CultureInfo.InvariantCulture)
                                        + ": 0x" + oldAbs.ToString("X", CultureInfo.InvariantCulture) + " -> 0x" + newAbs.ToString("X", CultureInfo.InvariantCulture)
                                        + (wok2 ? " (written)" : " (WRITE FAILED)"));
                                }
                                q = IndexOfAt(window, winLen, needle, q + 1);
                            }
                        }
                    }
                    int tailLen = Math.Min(OVERLAP, want);
                    Array.Copy(chunk, want - tailLen, tail, OVERLAP - tailLen, tailLen);
                    if (tailLen < OVERLAP) Array.Clear(tail, 0, OVERLAP - tailLen);
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

    // Phase 0 (v6): patch the STAGED copy of the injected DLL inside every ControlProc process,
    // BEFORE injection happens. Round 5 (15:57) proved the DLL's resolver caches hook RVAs within
    // ~1s of the game process starting - earlier than any external scan can reliably win. But the
    // DLL image is staged inside ControlProc first (manual-mapping loader), so rewriting the staged
    // dispatch there means the injected copy is BORN with the new RVAs. gaBase=0 -> qword pass skipped.
    private static void PatchStagedImages()
    {
        Process[] cps = Process.GetProcessesByName("ControlProc");
        if (cps.Length == 0) { Log("phase0: no ControlProc process found (start it before injecting)"); return; }
        foreach (Process cp in cps)
        {
            IntPtr h = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION, false, cp.Id);
            if (h == IntPtr.Zero) { Log("phase0: OpenProcess(ControlProc pid=" + cp.Id + ") failed (admin?)"); continue; }
            Log("phase0: scan-and-patch staged DLL in ControlProc pid=" + cp.Id + " ...");
            List<long> staged = FindDllBasesContentScan(h, 0);
            Log("phase0: ControlProc pid=" + cp.Id + " -> " + staged.Count + " verified staged image(s) found & lea-patched");
            CloseHandle(h);
        }
    }

    public static int Main(string[] args)
    {
        // persistent logfile so the patch trail survives console close.
        // ALWAYS on by default (patcher_run_<timestamp>.log next to the exe); --no-logfile disables.
        string logfile = null;
        System.IO.StreamWriter logWriter = null;
        string procName = "Maplestory_Classic";
        int durationSec = 30, intervalMs = 20, waitSec = 180;
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

        // PHASE 0: patch staged DLL images inside ControlProc BEFORE injection.
        // This is the decisive fix from round 5: the DLL's resolver caches RVAs within ~1s of the
        // game process starting (faster than we can win in-game), but the image is staged inside
        // ControlProc first - patch it there and the injected copy is born with new RVAs.
        if (!verifyOnly) PatchStagedImages();
        else Log("phase0: skipped (verify-only)");

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
        long gaBaseEarly = 0;
        while (DateTime.Now < waitDeadline && bases.Count == 0)
        {
            // tier A: fast region-base signature check (cheap, every poll).
            bases = FindDllBases(hProc, checkedRegions);
            if (bases.Count > 0) { Log("detection: fast path (region-base signature) hit"); break; }

            // tier B (v6): scan-AND-patch content pass. Starts +0.3s after the process appears
            // (round 5: resolver caches RVAs from ~+0.3s), repeats every 0.4s. Each pass rewrites
            // every old-RVA lea and every (gaBase+oldRVA) qword cache it finds, anywhere in private
            // memory, and collects verified bases for the targeted re-patch loop.
            if (gaBaseEarly == 0) gaBaseEarly = GetModuleBase(pid, "GameAssembly.dll");
            double aliveSec = (DateTime.Now - procSeenAt).TotalSeconds;
            if (aliveSec >= 0.3 && (DateTime.Now - lastContentScan).TotalSeconds >= 0.4)
            {
                lastContentScan = DateTime.Now;
                List<long> scanFound = FindDllBasesContentScan(hProc, gaBaseEarly);
                foreach (long b in scanFound) if (!bases.Contains(b)) bases.Add(b);
                if (bases.Count > 0) { Log("detection: content scan hit (" + bases.Count + " base(s))"); break; }
            }
            Thread.Sleep(50);
        }
        if (bases.Count == 0)
        {
            Log("ERROR: injected DLL not found within wait window.");
            Log("running one final scan-and-patch pass before giving up...");
            if (gaBaseEarly == 0) gaBaseEarly = GetModuleBase(pid, "GameAssembly.dll");
            List<long> finalFound = FindDllBasesContentScan(hProc, gaBaseEarly);
            foreach (long b in finalFound) if (!bases.Contains(b)) bases.Add(b);
        }
        if (bases.Count == 0)
        {
            Log("ERROR: still not found after final scan. The DLL was likely never injected");
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
        DateTime lastFullScan = DateTime.Now;
        DateTime lastStagedRepatch = DateTime.Now;
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

            // v6: periodic full scan-and-patch (every ~1.5s) to catch qword caches the resolver
            // creates between passes and any lea the DLL restores from a template. This is the
            // safety net behind phase-0 staged patching.
            if ((DateTime.Now - lastFullScan).TotalSeconds >= 1.5)
            {
                lastFullScan = DateTime.Now;
                List<long> sf = FindDllBasesContentScan(hProc, gaBase);
                foreach (long b in sf) if (!bases.Contains(b)) { bases.Add(b); Log("  late-discovered base 0x" + b.ToString("X", CultureInfo.InvariantCulture)); }
            }
            // v6: periodically re-patch ControlProc staged images (in case of re-stage / multi-slot)
            if ((DateTime.Now - lastStagedRepatch).TotalSeconds >= 5.0)
            {
                lastStagedRepatch = DateTime.Now;
                PatchStagedImages();
            }
            Thread.Sleep(intervalMs);
        }
        Log("done. passes=" + pass + " patchesApplied=" + patchCount);
        Log("verify in game dir hook_artifacts\\diagnostics: invincible-hook.log targets should be base+0x12144F0/+0x1214940/+0x1215270/+0x10D74B0; imgui-startup.log Update should install (rva=0x14DB0B0), no crash.");
        CloseHandle(hProc);
        if (logWriter != null) logWriter.Close();
        return 0;
    }
}
