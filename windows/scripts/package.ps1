param(
    [ValidateSet('Debug', 'Release')][string]$Configuration = 'Release',
    [switch]$Msi,
    [switch]$IncludeCore,
    [string]$WixPath = 'wix'
)
$ErrorActionPreference = 'Stop'
$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
$buildRoot = Join-Path $repoRoot 'build'
$binaryRoot = Join-Path $buildRoot "windows-$($Configuration.ToLowerInvariant())"
$stage = Join-Path $buildRoot ('windows-package-' + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $stage | Out-Null
# Explicitly package only our preview and its UI dependencies. The optional
# sing-box release is obtained separately using its pinned official archive.
foreach ($name in @('sb-easy.exe', 'sb-easy-service.exe', 'WebView2Loader.dll')) {
    Copy-Item -LiteralPath (Join-Path $binaryRoot $name) -Destination $stage
}
Copy-Item -LiteralPath (Join-Path $repoRoot 'windows\assets\sb-easy.ico') -Destination $stage
Copy-Item -LiteralPath (Join-Path $repoRoot 'windows\ui\dist') -Destination (Join-Path $stage 'ui') -Recurse
# All tools ship with the application. Isolated worker processes are an internal
# implementation detail; they no longer require store installation or markers.
foreach ($id in @('capture','statistics','http-debug')) {
    $destination=Join-Path $stage "extensions/$id"
    New-Item -ItemType Directory -Path $destination | Out-Null
    $worker=Join-Path $binaryRoot "extensions/$id/sb-easy-$id.exe"
    if(-not (Test-Path -LiteralPath $worker)){throw "Build the bundled $id engine before packaging."}
    Copy-Item -LiteralPath $worker -Destination $destination
}
Copy-Item -LiteralPath (Join-Path $binaryRoot 'extensions/capture/capture') -Destination (Join-Path $stage 'extensions/capture/capture') -Recurse
New-Item -ItemType Directory -Path (Join-Path $stage 'licenses'),(Join-Path $stage 'scripts') | Out-Null
foreach ($name in @('sbj-grisu2-MIT.txt', 'webview2.txt', 'webview2-notice.txt', 'vue.txt', 'tldts.txt', 'tldts-core.txt', 'yaml.txt')) {
    Copy-Item -LiteralPath (Join-Path $binaryRoot "licenses\$name") -Destination (Join-Path $stage 'licenses')
}
foreach ($name in @('http-debug.txt','WinDivert.txt','libpcap.txt')) {
    Copy-Item -LiteralPath (Join-Path $binaryRoot "licenses/$name") -Destination (Join-Path $stage 'licenses')
}
foreach ($name in @('README.md', 'THIRD_PARTY_NOTICES.md', 'TESTING-0.5.0.txt', 'TESTING-0.6.0.txt', 'TESTING-0.6.1.txt', 'ANDROID-PARITY.md')) {
    Copy-Item -LiteralPath (Join-Path $repoRoot "windows\$name") -Destination $stage
}
Copy-Item -LiteralPath (Join-Path $PSScriptRoot 'prepare-core.ps1') -Destination (Join-Path $stage 'scripts')
Copy-Item -LiteralPath (Join-Path $PSScriptRoot 'collect-diagnostics.ps1') -Destination (Join-Path $stage 'scripts')
Copy-Item -LiteralPath (Join-Path $PSScriptRoot 'Export-Diagnostics.cmd') -Destination $stage
if ($IncludeCore) {
    # Re-verify the pinned upstream archive; do not package arbitrary core files
    # found in a developer's build directory.
    & (Join-Path $PSScriptRoot 'prepare-core.ps1') -Configuration $Configuration
    New-Item -ItemType Directory -Path (Join-Path $stage 'core') | Out-Null
    foreach ($name in @('sing-box.exe', 'libcronet.dll', 'LICENSE')) {
        Copy-Item -LiteralPath (Join-Path $binaryRoot "core\$name") -Destination (Join-Path $stage 'core')
    }
}
$archive = Join-Path $buildRoot 'sb-easy-0.7.1-windows-x64-portable.zip'
Compress-Archive -Path (Join-Path $stage '*') -DestinationPath $archive -Force
Write-Output "Windows preview packaged at $archive"
Get-FileHash -LiteralPath $archive -Algorithm SHA256
if ($Msi) {
    & (Join-Path $PSScriptRoot 'package-msi.ps1') -Payload $stage -WixPath $WixPath
}
