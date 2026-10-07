param([ValidateSet('Debug', 'Release')][string]$Configuration = 'Release')
$ErrorActionPreference = 'Stop'
$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
$sourceCheckout = Test-Path -LiteralPath (Join-Path $repoRoot 'windows\CMakeLists.txt')
$destinationRoot = if ($sourceCheckout) {
    Join-Path $repoRoot "build\windows-$($Configuration.ToLowerInvariant())"
} else {
    # The portable preview places this script in its scripts/ directory.
    (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
}
$version = '1.13.12'
# v1.13.12 pins sing-tun v0.8.9, whose Windows amd64 adapter embeds Wintun
# and loads those bytes directly (no adjacent wintun.dll is consulted):
# https://github.com/SagerNet/sing-box/blob/v1.13.12/go.mod
# https://github.com/SagerNet/sing-tun/blob/v0.8.9/internal/wintun/dll_windows_amd64.go
# https://github.com/SagerNet/sing-tun/blob/v0.8.9/internal/wintun/dll_windows.go
# Do not download an unused second Wintun DLL or install a driver here.
$expectedHash = 'E93FC531134EB1BEB4EFA3C74990A24E48456098A31C03B60D5DDF17F223CF98'
$downloadDir = if ($sourceCheckout) { Join-Path $repoRoot 'build\core-download' } else { Join-Path $destinationRoot 'downloads' }
$archive = Join-Path $downloadDir "sing-box-$version-windows-amd64.zip"
New-Item -ItemType Directory -Path $downloadDir -Force | Out-Null
if (-not (Test-Path -LiteralPath $archive)) {
    Invoke-WebRequest -Uri "https://github.com/SagerNet/sing-box/releases/download/v$version/sing-box-$version-windows-amd64.zip" -OutFile $archive
}
if ((Get-FileHash -LiteralPath $archive -Algorithm SHA256).Hash -ne $expectedHash) {
    throw 'The core archive does not match the pinned official release checksum. It was not installed.'
}
$extractDir = Join-Path $downloadDir ('verified-' + [guid]::NewGuid().ToString('N'))
Expand-Archive -LiteralPath $archive -DestinationPath $extractDir
$sourceDir = Join-Path $extractDir "sing-box-$version-windows-amd64"
$coreDir = Join-Path $destinationRoot 'core'
New-Item -ItemType Directory -Path $coreDir -Force | Out-Null
foreach ($name in @('sing-box.exe', 'libcronet.dll', 'LICENSE')) {
    Copy-Item -LiteralPath (Join-Path $sourceDir $name) -Destination (Join-Path $coreDir $name)
}
Write-Output "Pinned sing-box $version prepared at $coreDir. No core or VPN was started."
Write-Output 'This core embeds Wintun; no separate wintun.dll download is required.'
