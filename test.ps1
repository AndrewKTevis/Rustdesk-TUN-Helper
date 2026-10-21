param([switch]$NetworkChecks)
$ErrorActionPreference = 'Stop'
$root = $PSScriptRoot
$testDirectory = Join-Path $root 'build\tests'
& (Join-Path $root 'build.ps1') -Tests -Distribution $testDirectory
$report = Join-Path $testDirectory 'results.json'
& (Join-Path $testDirectory 'RustdeskTUNHelper.Tests.exe') $report
if ($LASTEXITCODE -ne 0) { throw ('Regression tests failed: ' + $report) }
& (Join-Path $root 'build.ps1')
if ($NetworkChecks) {
    $exe = Join-Path $root 'outputs\Rustdesk-TUN-Helper\Rustdesk Clash-TUN Helper.exe'
    $report = Join-Path $testDirectory 'network.json'
    $start = New-Object Diagnostics.ProcessStartInfo($exe, ('--self-test "' + $report + '"'))
    $start.UseShellExecute = $false
    $process = [Diagnostics.Process]::Start($start)
    if (!$process.WaitForExit(25000)) { $process.Kill(); throw 'Network checks timed out' }
    if ($process.ExitCode -ne 0) { throw ('Network checks failed: ' + $report) }
    Get-Content -LiteralPath $report -Raw
}
