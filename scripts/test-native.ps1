$ErrorActionPreference='Stop'
$root=Split-Path $PSScriptRoot -Parent
$nativeRoot=Join-Path $root 'build\native-checks'
& (Join-Path $root 'build.ps1') -NativeChecks -Distribution $nativeRoot
$runId=[Guid]::NewGuid().ToString('N')
$sid=[Security.Principal.WindowsIdentity]::GetCurrent().User.Value
$data=Join-Path ([Environment]::GetFolderPath('CommonApplicationData')) ('RustdeskTUNHelper-Checks-'+$runId+'\'+$sid)
$native=Join-Path $nativeRoot 'RustdeskTUNHelper.NativeChecks.exe'
$output=Join-Path $nativeRoot ('run-'+$runId)
New-Item -ItemType Directory -Path $output -Force | Out-Null
@{id=$runId;data=$data;output=$output;binary=$native} | ConvertTo-Json | Set-Content (Join-Path $nativeRoot 'native-run.json') -Encoding UTF8
$ready=Join-Path $data 'pipe-ready.json'
$job=Start-Job -ArgumentList $ready -ScriptBlock {
 param($readyFile)
 Start-Sleep -Seconds 45
 if(!(Test-Path -LiteralPath $readyFile)){foreach($i in 1..3){[Console]::Beep(950,220);Start-Sleep -Milliseconds 180}}
}
try {
 [Media.SystemSounds]::Exclamation.Play()
 $start=[Diagnostics.ProcessStartInfo]::new($native,('--admin '+$runId))
 $start.UseShellExecute=$true; $start.Verb='runas'; $start.WindowStyle=[Diagnostics.ProcessWindowStyle]::Hidden
 $process=[Diagnostics.Process]::Start($start)
 $deadline=[Diagnostics.Stopwatch]::StartNew(); $clientDone=$false; $uiDone=$false
 while(!$process.HasExited -and $deadline.Elapsed.TotalSeconds -lt 110){
  if(!$clientDone -and (Test-Path -LiteralPath $ready)){
   $endpoint=Get-Content -LiteralPath $ready -Raw | ConvertFrom-Json
   $client=[Diagnostics.ProcessStartInfo]::new($native,('--client '+$endpoint.name+' "'+$data+'" "'+(Join-Path $output 'client-results.json')+'"'))
   $client.UseShellExecute=$false; $client.CreateNoWindow=$true
   $clientProcess=[Diagnostics.Process]::Start($client)
   if(!$clientProcess.WaitForExit(30000)){throw 'Client tests timeout'}
   $clientDone=$true
  }
  $uiReady=Join-Path $data 'ui-ready.json'
  if(!$uiDone -and (Test-Path -LiteralPath $uiReady)){
   $endpoint=Get-Content -LiteralPath $uiReady -Raw | ConvertFrom-Json
   $ui=[Diagnostics.ProcessStartInfo]::new($native,('--ui-client '+$endpoint.name+' "'+(Join-Path $output 'ui-client-results.json')+'"'))
   $ui.UseShellExecute=$false; $ui.CreateNoWindow=$true
   $uiProcess=[Diagnostics.Process]::Start($ui)
   if(!$uiProcess.WaitForExit(20000)){throw 'Tray client timeout'}
   $uiDone=$true
  }
  Start-Sleep -Milliseconds 200
 }
 if(!$process.HasExited){throw 'Native tests timeout'}
 foreach($name in @('result.json','progress.json','expiry.json','fatal.json')){
  $source=Join-Path $data $name
  if(Test-Path -LiteralPath $source){Copy-Item -LiteralPath $source -Destination (Join-Path $output $name)}
 }
 @{exitCode=$process.ExitCode;runId=$runId;data=$data;output=$output} | ConvertTo-Json | Set-Content (Join-Path $output 'run.json') -Encoding UTF8
 Write-Output ('Native exit: '+$process.ExitCode)
 foreach($name in @('result.json','client-results.json','ui-client-results.json','fatal.json')){if(Test-Path -LiteralPath (Join-Path $output $name)){Get-Content -LiteralPath (Join-Path $output $name) -Raw}}
}finally{
 Stop-Job -Job $job -ErrorAction SilentlyContinue
 Remove-Job -Job $job -Force -ErrorAction SilentlyContinue
}
