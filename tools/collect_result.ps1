# collect_result.ps1 - post-injection result summary (run AFTER the test)
# Resolves the diagnostics dir from D:\9-4\xxx\config.json (maple_story_path), avoiding
# hardcoded non-ASCII literals (PS 5.1 ANSI parsing of UTF-8 scripts).
# Usage:
#   powershell -NoProfile -ExecutionPolicy Bypass -File collect_result.ps1
#   optional: -DiagPath <dir> -InvBase <lines> -ImgBase <lines> -Minutes 15
param(
    [string]$DiagPath = $null,
    [int]$InvBase = 276,
    [int]$ImgBase = 794,
    [int]$Minutes = 15
)

if (-not $DiagPath) {
    try {
        $cfg = Get-Content "D:\9-4\xxx\config.json" -Raw -Encoding UTF8 | ConvertFrom-Json
        if ($cfg.maple_story_path) {
            $DiagPath = Join-Path (Split-Path $cfg.maple_story_path) "hook_artifacts\diagnostics"
        }
    } catch { }
}
if (-not $DiagPath -or -not (Test-Path $DiagPath)) {
    Write-Host "ERROR: cannot locate diagnostics dir ($DiagPath). Use -DiagPath."
    exit 1
}
Write-Host "diagnostics dir: $DiagPath`n"

function Dump-New($file, $base) {
    $p = Join-Path $DiagPath $file
    if (-not (Test-Path $p)) { Write-Host "(missing $file)"; return }
    $lines = Get-Content $p
    if ($lines.Count -gt $base) {
        for ($i = $base; $i -lt $lines.Count; $i++) { Write-Host $lines[$i] }
    } else { Write-Host "(no new lines in $file; total $($lines.Count))" }
}

Write-Host "===== invincible-hook.log (new) =====" -ForegroundColor Cyan
Dump-New "invincible-hook.log" $InvBase

Write-Host "`n===== imgui-startup.log (new) =====" -ForegroundColor Cyan
Dump-New "imgui-startup.log" $ImgBase

Write-Host "`n===== security-lease.log (tail 8) =====" -ForegroundColor Cyan
$sec = Join-Path $DiagPath "security-lease.log"
if (Test-Path $sec) { Get-Content $sec -Tail 8 | ForEach-Object { Write-Host $_ } }

Write-Host "`n===== crash events (Application/1000, last $Minutes min, game modules) =====" -ForegroundColor Cyan
try {
    $since = (Get-Date).AddMinutes(-$Minutes)
    $ev = Get-WinEvent -FilterHashtable @{LogName='Application'; Id=1000; StartTime=$since} -ErrorAction Stop |
          Where-Object { $_.Message -match 'Maplestory|MapleStory|GameAssembly' }
    if ($ev) {
        foreach ($e in $ev) {
            $m = $e.Message
            $mod = if ($m -match 'Faulting module name:\s*(\S+)') { $Matches[1] } else { '?' }
            $off = if ($m -match 'Fault offset:\s*(\S+)') { $Matches[1] } else { '?' }
            $code = if ($m -match 'Exception code:\s*(\S+)') { $Matches[1] } else { '?' }
            Write-Host ("  [{0:HH:mm:ss}] module={1} offset={2} code={3}" -f $e.TimeCreated, $mod, $off, $code) -ForegroundColor Red
        }
    } else { Write-Host "  (no crash events) GOOD" -ForegroundColor Green }
} catch { Write-Host "  (event query failed: $($_.Exception.Message))" }

Write-Host "`n===== verdict hints =====" -ForegroundColor Yellow
Write-Host "  invincible 4 hooks expect base+0x12144F0 / +0x1214940 / +0x1215270 / +0x10D74B0  (MH_OK)"
Write-Host "  imgui Update expect 'installed=1  rva=0x14DB0B0'  (NOT 'rejected')"
Write-Host "  no new Event 1000 => crash fixed"