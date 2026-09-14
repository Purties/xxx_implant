# read_bytes.ps1 - PE RVA -> file offset -> hex dump (read-only)
param(
  [string]$PePath,
  [string]$OutFile,
  [string]$RvaList,
  [int]$Before = 32,
  [int]$After = 96
)
[uint64[]]$Rvas = $RvaList.Split(',') | ForEach-Object { [Convert]::ToUInt64($_.Trim(), 16) }

$fs = [System.IO.File]::OpenRead($PePath)
$br = New-Object System.IO.BinaryReader($fs)

# DOS header -> e_lfanew
$fs.Seek(0x3C, 'Begin') | Out-Null
$peOff = $br.ReadUInt32()
$fs.Seek($peOff, 'Begin') | Out-Null
$sig = $br.ReadUInt32()
if ($sig -ne 0x00004550) { throw "not a PE" }

# COFF header
$machine = $br.ReadUInt16()
$numSecs = $br.ReadUInt16()
$br.ReadUInt32() | Out-Null  # TimeDateStamp
$br.ReadUInt32() | Out-Null  # PtrToSym
$br.ReadUInt32() | Out-Null  # NumSym
$optSize = $br.ReadUInt16()
$br.ReadUInt16() | Out-Null  # Characteristics

# Optional header: magic
$optStart = $fs.Position
$magic = $br.ReadUInt16()
$is64 = ($magic -eq 0x20B)
$fs.Seek($optStart + $optSize, 'Begin') | Out-Null

# Section headers
$secs = @()
for ($i = 0; $i -lt $numSecs; $i++) {
  $nameBytes = $br.ReadBytes(8)
  $name = ([System.Text.Encoding]::ASCII.GetString($nameBytes)).TrimEnd([char]0)
  $vsize = $br.ReadUInt32()
  $vaddr = $br.ReadUInt32()
  $rawSize = $br.ReadUInt32()
  $rawPtr = $br.ReadUInt32()
  $fs.Seek(16, 'Current') | Out-Null  # reloc/line nums/chars
  $secs += [pscustomobject]@{ Name=$name; VAddr=$vaddr; VSize=$vsize; RawPtr=$rawPtr; RawSize=$rawSize }
}

function RvaToOff([uint64]$rva) {
  foreach ($s in $secs) {
    if ($rva -ge $s.VAddr -and $rva -lt ($s.VAddr + [Math]::Max($s.VSize, $s.RawSize))) {
      return $s.RawPtr + ($rva - $s.VAddr)
    }
  }
  return $null
}

$out = New-Object System.Text.StringBuilder
[void]$out.AppendLine("PE: $PePath  sections=$numSecs  is64=$is64")
foreach ($s in $secs) {
  [void]$out.AppendLine(("  {0,-10} VA=0x{1:x8} VSize=0x{2:x8} RawPtr=0x{3:x8} RawSize=0x{4:x8}" -f $s.Name,$s.VAddr,$s.VSize,$s.RawPtr,$s.RawSize))
}

foreach ($rva in $Rvas) {
  $start = $rva - $Before
  $off = RvaToOff $start
  $len = $Before + $After
  [void]$out.AppendLine("")
  [void]$out.AppendLine(("=== RVA 0x{0:x}  (range 0x{1:x}..0x{2:x}) ===" -f $rva, $start, ($start+$len)))
  if ($null -eq $off) { [void]$out.AppendLine("  RVA not mapped"); continue }
  $fs.Seek($off, 'Begin') | Out-Null
  $buf = $br.ReadBytes($len)
  for ($i = 0; $i -lt $buf.Length; $i += 16) {
    $addr = $start + $i
    $hex = ($buf[$i..([Math]::Min($i+15, $buf.Length-1))] | ForEach-Object { $_.ToString("x2") }) -join ' '
    $mark = ""
    if ($rva -ge $addr -and $rva -lt ($addr+16)) { $mark = "   <-- target 0x{0:x}" -f $rva }
    [void]$out.AppendLine(("  0x{0:x12}: {1,-47}{2}" -f $addr, $hex, $mark))
  }
}

$fs.Close()
[System.IO.File]::WriteAllText($OutFile, $out.ToString())
Write-Host "written: $OutFile"
