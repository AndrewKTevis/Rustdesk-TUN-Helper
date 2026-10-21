param([string]$Distribution = '', [switch]$Tests, [switch]$NativeChecks)
$ErrorActionPreference = 'Stop'
$root = $PSScriptRoot
$deps = Join-Path $root 'tools\traceevent-2.0.75'
$build = Join-Path $root 'build\resources'
$dist = if ($Distribution) { [IO.Path]::GetFullPath($Distribution) } else { Join-Path $root 'outputs\Rustdesk-TUN-Helper' }
New-Item -ItemType Directory -Force $build, $dist | Out-Null

$libraries = @('Microsoft.Diagnostics.Tracing.TraceEvent', 'Microsoft.Diagnostics.FastSerialization', 'OSExtensions', 'System.Runtime.CompilerServices.Unsafe', 'Dia2Lib', 'TraceReloggerLib')
$manifest = Get-Content -LiteralPath (Join-Path $root 'assets\dependencies.json') -Raw | ConvertFrom-Json
if ($manifest.dependencies.Count -ne $libraries.Count) { throw 'Invalid dependency manifest' }
$resources = foreach ($name in $libraries) {
    $library = Join-Path $deps ($name + '.dll')
    if (!(Test-Path -LiteralPath $library)) { throw "Missing dependency $library. Run scripts\bootstrap-dependencies.ps1 first." }
    $expected = @($manifest.dependencies | Where-Object file -EQ ($name + '.dll'))
    if ($expected.Count -ne 1 -or (Get-FileHash -LiteralPath $library -Algorithm SHA256).Hash -cne $expected[0].sha256) { throw ('Dependency hash mismatch: ' + $name) }
    $destination = Join-Path $build ($name + '.deflate')
    $file = [IO.File]::Create($destination)
    $zip = [IO.Compression.DeflateStream]::new($file, [IO.Compression.CompressionMode]::Compress)
    try {
        $bytes = [IO.File]::ReadAllBytes($library)
        $zip.Write($bytes, 0, $bytes.Length)
    } finally { $zip.Dispose(); $file.Dispose() }
    '/resource:' + $destination + ',' + $name + '.deflate'
}
$resources += '/resource:' + (Join-Path $root 'assets\dependencies.json') + ',dependencies.json'
foreach ($license in @('LICENSE','third-party\TraceEvent-LICENSE.TXT','third-party\Unsafe-LICENSE.TXT','third-party\Unsafe-THIRD-PARTY-NOTICES.TXT')) {
    $resources += '/resource:' + (Join-Path $root $license) + ',licenses.' + [IO.Path]::GetFileName($license)
}
$sources = Get-ChildItem -LiteralPath (Join-Path $root 'src') -Filter '*.cs' -Recurse | Sort-Object FullName | ForEach-Object FullName
if ($Tests) { $sources += Join-Path $root 'tests\RegressionTests.cs' }
if ($NativeChecks) { $sources += Join-Path $root 'tests\NativeChecks.cs' }
$entry = if ($NativeChecks) { 'NativeChecks' } elseif ($Tests) { 'RegressionTests' } else { 'Program' }
$target = if ($Tests -or $NativeChecks) { 'exe' } else { 'winexe' }
$binary = if ($NativeChecks) { 'RustdeskTUNHelper.NativeChecks.exe' } elseif ($Tests) { 'RustdeskTUNHelper.Tests.exe' } else { 'Rustdesk Clash-TUN Helper.exe' }
$compiler = Join-Path $env:WINDIR 'Microsoft.NET\Framework64\v4.0.30319\csc.exe'
& $compiler /nologo /optimize+ /platform:x64 ("/target:" + $target) ("/main:" + $entry) /warn:4 /warnaserror+ /reference:System.Windows.Forms.dll /reference:System.Drawing.dll /reference:System.Web.Extensions.dll /reference:System.Management.dll ("/reference:" + (Join-Path $deps 'Microsoft.Diagnostics.Tracing.TraceEvent.dll')) ("/reference:" + (Join-Path $deps 'Microsoft.Diagnostics.FastSerialization.dll')) ("/win32manifest:" + (Join-Path $root 'src\App\app.manifest')) ("/win32icon:" + (Join-Path $root 'assets\app.ico')) ("/out:" + (Join-Path $dist $binary)) $resources $sources
if ($LASTEXITCODE -ne 0) { throw 'Compilation failed' }
Get-FileHash -LiteralPath (Join-Path $dist $binary)
