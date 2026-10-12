param(
    [ValidateSet('Debug', 'Release')][string]$Configuration = 'Release',
    [switch]$Msi,
    [switch]$IncludeCore,
    [string]$WixPath = 'wix'
)
$ErrorActionPreference = 'Stop'
$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
if ((Get-Content -LiteralPath (Join-Path $repoRoot 'windows/service/store_catalog.h') -Raw) -match 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855') { throw 'Bootstrap catalog cannot ship. Run package-plugins.py and rebuild the base first.' }
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
New-Item -ItemType Directory -Path (Join-Path $stage 'licenses'),(Join-Path $stage 'scripts') | Out-Null
foreach ($name in @('sbj-grisu2-MIT.txt', 'webview2.txt', 'webview2-notice.txt', 'vue.txt', 'tldts.txt', 'tldts-core.txt', 'yaml.txt')) {
    Copy-Item -LiteralPath (Join-Path $binaryRoot "licenses\$name") -Destination (Join-Path $stage 'licenses')
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
$archive = Join-Path $buildRoot 'sb-easy-0.6.8-windows-x64-portable.zip'
Compress-Archive -Path (Join-Path $stage '*') -DestinationPath $archive -Force
Write-Output "Windows preview packaged at $archive"
Get-FileHash -LiteralPath $archive -Algorithm SHA256
if ($Msi) {
    & (Join-Path $PSScriptRoot 'package-msi.ps1') -Payload $stage -WixPath $WixPath
}
