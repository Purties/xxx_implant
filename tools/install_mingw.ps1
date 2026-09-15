# install_mingw.ps1 - 从清华镜像安装 MinGW-w64 工具链到 C:\workspace\tools\mingw64
$ErrorActionPreference = 'Stop'
$base = 'https://mirrors.tuna.tsinghua.edu.cn/msys2/mingw/mingw64/'
$dl = 'C:\workspace\downloads'
$prefix = 'C:\workspace\tools\mingw64'
New-Item -ItemType Directory -Force -Path $dl, $prefix | Out-Null

$pkgs = @(
  'mingw-w64-x86_64-binutils-2.47-3-any.pkg.tar.zst',
  'mingw-w64-x86_64-crt-14.0.0.r98.g19f5121a2-1-any.pkg.tar.zst',
  'mingw-w64-x86_64-headers-14.0.0.r98.g19f5121a2-1-any.pkg.tar.zst',
  'mingw-w64-x86_64-libwinpthread-14.0.0.r98.g19f5121a2-1-any.pkg.tar.zst',
  'mingw-w64-x86_64-gmp-6.3.0-2-any.pkg.tar.zst',
  'mingw-w64-x86_64-mpfr-4.2.2-3-any.pkg.tar.zst',
  'mingw-w64-x86_64-mpc-1.4.1-1-any.pkg.tar.zst',
  'mingw-w64-x86_64-isl-0.28-1-any.pkg.tar.zst',
  'mingw-w64-x86_64-zstd-1.5.7-2-any.pkg.tar.zst',
  'mingw-w64-x86_64-libiconv-1.19-1-any.pkg.tar.zst',
  'mingw-w64-x86_64-windows-default-manifest-6.4-4-any.pkg.tar.zst',
  'mingw-w64-x86_64-gcc-16.2.0-3-any.pkg.tar.zst'
)

foreach ($p in $pkgs) {
  $dst = Join-Path $dl $p
  if (-not (Test-Path $dst)) {
    Write-Host "download $p"
    Invoke-WebRequest -Uri ($base + $p) -OutFile $dst -UseBasicParsing -TimeoutSec 600
  }
  Write-Host "extract  $p"
  & 'C:\Program Files\Python312\python.exe' -c "import zstandard,sys; open(sys.argv[2],'wb').write(zstandard.ZstdDecompressor().decompress(open(sys.argv[1],'rb').read(), max_output_size=2**31))" $dst ($dst -replace '\.zst$','')
  tar.exe -xf ($dst -replace '\.zst$','') -C $prefix
  Remove-Item ($dst -replace '\.zst$','') -Force
}

# gcc 可能依赖 libgcc（gcc-libs）；检查后补装
if (-not (Test-Path "$prefix\bin\libgcc_s_seh-1.dll")) {
  Write-Host 'looking up gcc-libs package...'
  $r = Invoke-WebRequest -Uri $base -UseBasicParsing -TimeoutSec 120
  $hrefs = [regex]::Matches($r.Content, 'href="([^"]+)"') | ForEach-Object { $_.Groups[1].Value }
  $lib = $hrefs | Where-Object { $_ -match '^mingw-w64-x86_64-gcc-libs-\d' -and $_ -notmatch '\.sig$' } | Sort-Object | Select-Object -Last 1
  if ($lib) {
    Write-Host "download+extract $lib"
    $dst = Join-Path $dl $lib
    Invoke-WebRequest -Uri ($base + $lib) -OutFile $dst -UseBasicParsing -TimeoutSec 600
    & 'C:\Program Files\Python312\python.exe' -c "import zstandard,sys; open(sys.argv[2],'wb').write(zstandard.ZstdDecompressor().decompress(open(sys.argv[1],'rb').read(), max_output_size=2**31))" $dst ($dst -replace '\.zst$','')
    tar.exe -xf ($dst -replace '\.zst$','') -C $prefix
    Remove-Item ($dst -replace '\.zst$','') -Force
  }
}

Write-Host '=== verify ==='
& "$prefix\bin\gcc.exe" --version | Select-Object -First 1
Write-Host 'DONE'
