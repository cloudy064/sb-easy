param([ValidateSet('Debug', 'Release')][string]$Configuration = 'Release')
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
Copy-Item -LiteralPath (Join-Path $repoRoot 'windows\ui\dist') -Destination (Join-Path $stage 'ui') -Recurse
New-Item -ItemType Directory -Path (Join-Path $stage 'licenses'),(Join-Path $stage 'scripts') | Out-Null
foreach ($name in @('sbj-grisu2-MIT.txt', 'webview2.txt', 'webview2-notice.txt', 'vue.txt')) {
    Copy-Item -LiteralPath (Join-Path $binaryRoot "licenses\$name") -Destination (Join-Path $stage 'licenses')
}
foreach ($name in @('README.md', 'THIRD_PARTY_NOTICES.md')) {
    Copy-Item -LiteralPath (Join-Path $repoRoot "windows\$name") -Destination $stage
}
Copy-Item -LiteralPath (Join-Path $PSScriptRoot 'prepare-core.ps1') -Destination (Join-Path $stage 'scripts')
$archive = Join-Path $buildRoot 'sb-easy-windows-x64-development-preview.zip'
Compress-Archive -Path (Join-Path $stage '*') -DestinationPath $archive -Force
Write-Output "Windows preview packaged at $archive"
Get-FileHash -LiteralPath $archive -Algorithm SHA256
