<#
    B站自律锁 · 一键编译
    用法：  powershell -ExecutionPolicy Bypass -File .\build.ps1
    产物：  项目根目录下的  B站自律锁.exe
#>
$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $MyInvocation.MyCommand.Definition
$csc  = Join-Path $env:WINDIR 'Microsoft.NET\Framework64\v4.0.30319\csc.exe'
if (-not (Test-Path $csc)) { $csc = Join-Path $env:WINDIR 'Microsoft.NET\Framework\v4.0.30319\csc.exe' }
if (-not (Test-Path $csc)) { throw '找不到 csc.exe，请确认已安装 .NET Framework 4.x' }

$src = Join-Path $root 'src\BiliLock.cs'
$man = Join-Path $root 'src\app.manifest'
$out = Join-Path $root 'B站自律锁.exe'

Write-Host "编译器: $csc"
& $csc /nologo /target:winexe /platform:anycpu /optimize+ /codepage:65001 `
    /r:System.dll /r:System.Drawing.dll /r:System.Windows.Forms.dll /r:System.Core.dll `
    "/win32manifest:$man" "/out:$out" "$src"

if ($LASTEXITCODE -ne 0) { throw "编译失败，退出码 $LASTEXITCODE" }
Write-Host ("编译成功: {0}  ({1:N1} KB)" -f $out, ((Get-Item $out).Length / 1KB))