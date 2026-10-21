$ErrorActionPreference = 'Stop'
$root = Split-Path $PSScriptRoot -Parent
$output = Join-Path $root 'outputs'
$dist = Join-Path $output 'Rustdesk-TUN-Helper'
$exe = Join-Path $dist 'Rustdesk Clash-TUN Helper.exe'
if (!(Test-Path -LiteralPath $exe -PathType Leaf)) { throw 'Missing EXE; run test.ps1 first' }
$version = [Diagnostics.FileVersionInfo]::GetVersionInfo($exe).ProductVersion
if ($version -notmatch '^\d+\.\d+\.\d+(?:-[a-z0-9.]+)?$') { throw 'Invalid product version' }
Add-Type -AssemblyName System.IO.Compression
Add-Type -AssemblyName System.IO.Compression.FileSystem
Add-Type -AssemblyName Microsoft.VisualBasic
function Recycle-Archive([string]$path) {
    if (Test-Path -LiteralPath $path) {
        if ((Get-Item -LiteralPath $path).Attributes -band [IO.FileAttributes]::ReparsePoint) { throw ('Linked output: ' + $path) }
        [Microsoft.VisualBasic.FileIO.FileSystem]::DeleteFile($path, [Microsoft.VisualBasic.FileIO.UIOption]::OnlyErrorDialogs, [Microsoft.VisualBasic.FileIO.RecycleOption]::SendToRecycleBin)
    }
}
function Write-Archive([string]$path, $items) {
    Recycle-Archive $path
    $zip = [IO.Compression.ZipFile]::Open($path, [IO.Compression.ZipArchiveMode]::Create)
    try {
        foreach ($item in $items) {
            if ((Get-Item -LiteralPath $item.path).Attributes -band [IO.FileAttributes]::ReparsePoint) { throw ('Linked source: ' + $item.path) }
            [IO.Compression.ZipFileExtensions]::CreateEntryFromFile($zip, $item.path, $item.name) | Out-Null
        }
    } finally { $zip.Dispose() }
}
$sourceFiles = @('README.md', 'README.zh-CN.md', 'LICENSE', 'SECURITY.md', '.gitignore', 'build.ps1', 'test.ps1') | ForEach-Object { Get-Item -LiteralPath (Join-Path $root $_) }
foreach ($folder in @('src', 'scripts', 'assets', 'docs', 'tests', 'third-party', '.github')) {
    $directory = Get-Item -LiteralPath (Join-Path $root $folder)
    if ($directory.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw ('Linked source directory: ' + $directory.FullName) }
    $children = @(Get-ChildItem -LiteralPath $directory.FullName -Recurse -Force)
    if (@($children | Where-Object { $_.Attributes -band [IO.FileAttributes]::ReparsePoint }).Count) { throw ('Linked source entry: ' + $folder) }
    $sourceFiles += $children | Where-Object { !$_.PSIsContainer }
}
foreach ($file in $sourceFiles) {
    if ($file.FullName -eq (Join-Path $root 'README.zh-CN.md')) { continue }
    if ($file.FullName.StartsWith((Join-Path $root 'third-party') + '\', [StringComparison]::OrdinalIgnoreCase)) { continue }
    if ($file.Extension -in @('.cs','.ps1','.md','.txt','.yml','.manifest','.json')) {
        $content = [IO.File]::ReadAllText($file.FullName)
        if ($file.FullName -eq (Join-Path $root 'README.md')) { $content = $content -replace '(?m)^\[[^\]\r\n]+\]\(README\.zh-CN\.md\)\r?$', '' }
        if ($content -match '[\p{IsCJKUnifiedIdeographs}\p{IsHiragana}\p{IsKatakana}]') { throw ('Non-English release text: ' + $file.FullName) }
    }
}
$source = Join-Path $output ('Rustdesk-TUN-Helper-' + $version + '-source.zip')
$entries = $sourceFiles | Sort-Object FullName | ForEach-Object { @{path=$_.FullName;name=$_.FullName.Substring($root.Length+1).Replace('\','/')} }
Write-Archive $source $entries
foreach ($file in @('LICENSE','README.md','README.zh-CN.md','SECURITY.md','assets\dependencies.json')) {
    Copy-Item -LiteralPath (Join-Path $root $file) -Destination $dist -Force
}
Get-ChildItem -LiteralPath (Join-Path $root 'third-party') -File | Copy-Item -Destination $dist -Force
@{name='Rustdesk Clash-TUN Helper';version=$version;platform='win-x64';language='en-US';signed=$false;exeSha256=(Get-FileHash -LiteralPath $exe -Algorithm SHA256).Hash;sourceSha256=(Get-FileHash -LiteralPath $source -Algorithm SHA256).Hash} | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $dist 'release.json') -Encoding UTF8
$release = Join-Path $output ('Rustdesk-TUN-Helper-' + $version + '-win-x64.zip')
$releaseFiles = @('Rustdesk Clash-TUN Helper.exe','LICENSE','README.md','README.zh-CN.md','SECURITY.md','dependencies.json','release.json')
$releaseFiles += Get-ChildItem -LiteralPath (Join-Path $root 'third-party') -File | ForEach-Object Name
$entries = $releaseFiles | ForEach-Object { @{path=(Join-Path $dist $_);name=$_} }
Write-Archive $release $entries
$checksums = foreach ($file in @($exe,$source,$release)) { (Get-FileHash -LiteralPath $file -Algorithm SHA256).Hash + '  ' + [IO.Path]::GetFileName($file) }
$checksums | Set-Content -LiteralPath (Join-Path $output 'SHA256SUMS.txt') -Encoding ASCII
$checksums
