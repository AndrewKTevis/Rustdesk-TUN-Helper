$ErrorActionPreference='Stop'
$toolRoot=Join-Path (Split-Path $PSScriptRoot -Parent) 'tools'
$destination=Join-Path $toolRoot 'traceevent-2.0.75'
New-Item -ItemType Directory -Force $destination | Out-Null
Add-Type -AssemblyName System.IO.Compression.FileSystem
$packages=@(
    @{File='TraceEvent.2.0.75.nupkg';Url='https://api.nuget.org/v3-flatcontainer/microsoft.diagnostics.tracing.traceevent/2.0.75/microsoft.diagnostics.tracing.traceevent.2.0.75.nupkg';Hash='A68F96EC9C88EBC1B5D96E71A8F3FA7636B81831B58EA882659BEB5FF847D16B';Entries=@('lib/net45/Microsoft.Diagnostics.Tracing.TraceEvent.dll','lib/net45/Microsoft.Diagnostics.FastSerialization.dll','lib/net45/OSExtensions.dll','lib/net45/Dia2Lib.dll','lib/net45/TraceReloggerLib.dll')},
    @{File='Unsafe.4.5.2.nupkg';Url='https://api.nuget.org/v3-flatcontainer/system.runtime.compilerservices.unsafe/4.5.2/system.runtime.compilerservices.unsafe.4.5.2.nupkg';Hash='F1E5175C658ED8B2FBB804CC6727B6882A503844E7DA309C8D4846E9CA11E4EF';Entries=@('lib/netstandard1.0/System.Runtime.CompilerServices.Unsafe.dll')}
)
foreach($package in $packages){
    $path=Join-Path $toolRoot $package.File
    if(!(Test-Path -LiteralPath $path)){Invoke-WebRequest -Uri $package.Url -OutFile $path}
    if((Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash -cne $package.Hash){throw ('Package hash mismatch: '+$package.File)}
    $zip=[IO.Compression.ZipFile]::OpenRead($path)
    try{foreach($entryName in $package.Entries){$entry=$zip.GetEntry($entryName);if(!$entry){throw ('Missing library '+$entryName)};$library=Join-Path $destination ([IO.Path]::GetFileName($entryName));if((Test-Path -LiteralPath $library) -and ((Get-Item -LiteralPath $library).Attributes -band [IO.FileAttributes]::ReparsePoint)){throw ('Linked library path '+$library)};[IO.Compression.ZipFileExtensions]::ExtractToFile($entry,$library,$true);if((Get-AuthenticodeSignature -FilePath $library).Status -ne 'Valid'){throw ('Invalid Microsoft library signature: '+$library)}}}
    finally{$zip.Dispose()}
}
$manifest=Get-Content -LiteralPath (Join-Path (Split-Path $PSScriptRoot -Parent) 'assets\dependencies.json') -Raw | ConvertFrom-Json
foreach($item in $manifest.dependencies){
    if((Get-FileHash -LiteralPath (Join-Path $destination $item.file) -Algorithm SHA256).Hash -cne $item.sha256){throw ('Dependency hash mismatch: '+$item.file)}
}
Write-Output 'Dependencies verified.'
