$ErrorActionPreference = 'Stop'
$root = Split-Path $PSScriptRoot -Parent
$build = Join-Path $root 'build\status-preview'
New-Item -ItemType Directory -Path $build -Force | Out-Null
$exe = Join-Path $build 'PreviewStatus.exe'
$sources = @('src\App\AppInfo.cs','src\App\TrayIcons.cs','src\App\StatusWindow.cs','scripts\PreviewStatus.cs') | ForEach-Object {Join-Path $root $_}
& "$env:WINDIR\Microsoft.NET\Framework64\v4.0.30319\csc.exe" /nologo /target:winexe /reference:System.Drawing.dll /reference:System.Windows.Forms.dll ("/out:"+$exe) $sources
if ($LASTEXITCODE -ne 0) {throw 'Preview build failed'}
$process=Start-Process -FilePath $exe -ArgumentList ('"'+(Join-Path $build 'status.png')+'"') -WindowStyle Hidden -PassThru -Wait
if ($process.ExitCode -ne 0) {throw 'Preview failed'}
