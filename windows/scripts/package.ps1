param(
    [ValidateSet('Debug', 'Release')][string]$Configuration = 'Release',
    [switch]$Msi,
    [switch]$IncludeCore,
    [string]$WixPath = 'wix',
    [switch]$TrustedRelease,
    [string]$CertificateThumbprint,
    [uri]$TimestampUrl,
    [string]$SignToolPath = 'signtool.exe'
)
$ErrorActionPreference = 'Stop'
$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
$clientVersions = Get-Content -LiteralPath (Join-Path $repoRoot 'config/client-releases.json') -Raw | ConvertFrom-Json
$version = [string]$clientVersions.development.windows.version
if ($clientVersions.schema_version -ne 1 -or $version -notmatch '^(0|[1-9][0-9]{0,2})\.(0|[1-9][0-9]{0,2})\.(0|[1-9][0-9]{0,4})$') { throw 'Invalid Windows version in the client manifest.' }
$versionParts = $version.Split('.') | ForEach-Object { [int]$_ }
if ($versionParts[0] -gt 255 -or $versionParts[1] -gt 255 -or $versionParts[2] -gt 65535) { throw 'Windows version exceeds Windows Installer limits.' }
if ($TrustedRelease -and (-not $Msi -or -not $IncludeCore -or $CertificateThumbprint -notmatch '^[A-Fa-f0-9]{40}$' -or -not $TimestampUrl)) { throw 'Trusted release requires MSI, pinned core, publisher certificate thumbprint and an RFC3161 timestamp URL.' }
if ((Get-Content -LiteralPath (Join-Path $repoRoot 'windows/service/store_catalog.h') -Raw) -match 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855') { throw 'Bootstrap catalog cannot ship. Run package-plugins.py and rebuild the base first.' }
$buildRoot = Join-Path $repoRoot 'build'
$binaryRoot = Join-Path $buildRoot "windows-$($Configuration.ToLowerInvariant())"
$runtimeVersions = Get-Content -LiteralPath (Join-Path $repoRoot 'config/runtime-versions.json') -Raw | ConvertFrom-Json
$builtPublisher = & (Join-Path $binaryRoot 'sb-easy-service.exe') --publisher-info | ConvertFrom-Json
if ($LASTEXITCODE -ne 0 -or $builtPublisher.version -notin @($version, "$version-dev") -or $builtPublisher.core_version -ne $runtimeVersions.sing_box.version) { throw 'Rebuild the Windows binaries with the current application and core manifests before packaging.' }
foreach ($name in @('sb-easy.exe', 'sb-easy-service.exe', 'sb-easy-update.exe')) {
    $binaryVersion = [Diagnostics.FileVersionInfo]::GetVersionInfo((Join-Path $binaryRoot $name))
    if ($binaryVersion.ProductVersion -ne $builtPublisher.version) { throw "Rebuild mismatched package executable: $name" }
}
if ($TrustedRelease -and ($builtPublisher.publisher_thumbprint -ne $CertificateThumbprint -or $builtPublisher.version -ne $version)) { throw 'Rebuild with the trusted publisher thumbprint and manifest version before signing this release.' }
$stage = Join-Path $buildRoot ('windows-package-' + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $stage | Out-Null
# Explicitly package only our preview and its UI dependencies. The optional
# sing-box release is obtained separately using its pinned official archive.
foreach ($name in @('sb-easy.exe', 'sb-easy-service.exe', 'sb-easy-update.exe', 'WebView2Loader.dll')) {
    Copy-Item -LiteralPath (Join-Path $binaryRoot $name) -Destination $stage
}
Copy-Item -LiteralPath (Join-Path $repoRoot 'windows\assets\sb-easy.ico') -Destination $stage
Copy-Item -LiteralPath (Join-Path $repoRoot 'config\runtime-versions.json') -Destination (Join-Path $stage 'runtime-versions.json')
Copy-Item -LiteralPath (Join-Path $repoRoot 'config\client-releases.json') -Destination (Join-Path $stage 'client-releases.json')
Copy-Item -LiteralPath (Join-Path $repoRoot 'windows\ui\dist') -Destination (Join-Path $stage 'ui') -Recurse
New-Item -ItemType Directory -Path (Join-Path $stage 'licenses'),(Join-Path $stage 'scripts') | Out-Null
foreach ($name in @('sbj-grisu2-MIT.txt', 'webview2.txt', 'webview2-notice.txt', 'vue.txt', 'tldts.txt', 'tldts-core.txt', 'yaml.txt', 'libyaml.txt')) {
    Copy-Item -LiteralPath (Join-Path $binaryRoot "licenses\$name") -Destination (Join-Path $stage 'licenses')
}
foreach ($name in @('README.md', 'THIRD_PARTY_NOTICES.md', 'TESTING-0.5.0.txt', 'TESTING-0.6.0.txt', 'TESTING-0.6.1.txt', 'ANDROID-PARITY.md')) {
    Copy-Item -LiteralPath (Join-Path $repoRoot "windows\$name") -Destination $stage
}
Copy-Item -LiteralPath (Join-Path $PSScriptRoot 'prepare-core.ps1') -Destination (Join-Path $stage 'scripts')
Copy-Item -LiteralPath (Join-Path $PSScriptRoot 'collect-diagnostics.ps1') -Destination (Join-Path $stage 'scripts')
Copy-Item -LiteralPath (Join-Path $PSScriptRoot 'verify-release.ps1') -Destination (Join-Path $stage 'scripts')
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
if ($TrustedRelease) {
    $ownedFiles = @('sb-easy.exe', 'sb-easy-service.exe', 'sb-easy-update.exe', 'scripts\prepare-core.ps1', 'scripts\collect-diagnostics.ps1', 'scripts\verify-release.ps1') | ForEach-Object { Join-Path $stage $_ }
    & (Join-Path $PSScriptRoot 'sign-release.ps1') -Files $ownedFiles -CertificateThumbprint $CertificateThumbprint -TimestampUrl $TimestampUrl -SignToolPath $SignToolPath
}
$archive = Join-Path $buildRoot "sb-easy-$version-windows-x64-portable.zip"
Compress-Archive -Path (Join-Path $stage '*') -DestinationPath $archive -Force
Write-Output "Windows preview packaged at $archive"
Get-FileHash -LiteralPath $archive -Algorithm SHA256
if ($Msi) {
    & (Join-Path $PSScriptRoot 'package-msi.ps1') -Payload $stage -Version $version -WixPath $WixPath
    if ($TrustedRelease) {
        $installer = Join-Path $buildRoot "sb-easy-$version-windows-x64.msi"
        & (Join-Path $PSScriptRoot 'sign-release.ps1') -Files @($installer) -CertificateThumbprint $CertificateThumbprint -TimestampUrl $TimestampUrl -SignToolPath $SignToolPath
        & (Join-Path $PSScriptRoot 'write-release-manifest.ps1') -Artifacts @($archive, $installer) -Output (Join-Path $buildRoot "sb-easy-$version-windows-x64-release.json") -CertificateThumbprint $CertificateThumbprint -Version $version
    }
}
