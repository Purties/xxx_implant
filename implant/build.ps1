# build.ps1 — 编译自研注入模块与注入器（需先装好 MinGW-w64 工具链）
# 工具链：C:\workspace\tools\mingw64\mingw64（清华 MSYS2 镜像安装）
$ErrorActionPreference = 'Stop'
$env:PATH = 'C:\workspace\tools\mingw64\mingw64\bin;' + $env:PATH
$gcc = 'C:\workspace\tools\mingw64\mingw64\bin\gcc.exe'
$dir = Split-Path -Parent $MyInvocation.MyCommand.Path

New-Item -ItemType Directory -Force -Path "$dir\out" | Out-Null

& $gcc -shared -O2 -o "$dir\implant.dll" "$dir\implant.c"
if ($LASTEXITCODE -ne 0) { throw 'implant.dll build failed' }
Write-Host "implant.dll OK $((Get-Item "$dir\implant.dll").Length) bytes"

& $gcc -O2 -municode -o "$dir\inject.exe" "$dir\inject.c"
if ($LASTEXITCODE -ne 0) { throw 'inject.exe build failed' }
Write-Host "inject.exe OK $((Get-Item "$dir\inject.exe").Length) bytes"

Write-Host 'BUILD DONE'
