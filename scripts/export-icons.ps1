$ErrorActionPreference = 'Stop'
$root = Split-Path $PSScriptRoot -Parent
$build = Join-Path $root 'build\icon-tools'
New-Item -ItemType Directory -Path $build -Force | Out-Null
$exe = Join-Path $build 'ExportIcons.exe'
& "$env:WINDIR\Microsoft.NET\Framework64\v4.0.30319\csc.exe" /nologo /target:exe /reference:System.Drawing.dll ("/out:" + $exe) (Join-Path $root 'src\App\TrayIcons.cs') (Join-Path $PSScriptRoot 'ExportIcons.cs')
if ($LASTEXITCODE -ne 0) { throw 'Icon exporter compilation failed' }
& $exe (Join-Path $root 'assets')
if ($LASTEXITCODE -ne 0) { throw 'Icon export failed' }
