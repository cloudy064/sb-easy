[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string] $RuntimeDirectory,

    [string] $DependencyDirectory,

    [string] $OutputDirectory,

    [string] $LauncherPath,

    [ValidatePattern('^\d+\.\d+\.\d+$')]
    [string] $ProductVersion = '1.0.0',

    [ValidatePattern('^[0-9A-Fa-f]{40}$')]
    [string] $CertificateThumbprint,

    [string] $TimestampUrl = 'http://timestamp.digicert.com'
)

$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

$repositoryRoot = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$buildRoot = [System.IO.Path]::GetFullPath((Join-Path $repositoryRoot 'build'))
$workingRoot = Join-Path $buildRoot 'windows-installer'
$cacheRoot = Join-Path $buildRoot 'windows-installer-cache'
$runtimeRoot = [System.IO.Path]::GetFullPath($RuntimeDirectory)
if ([string]::IsNullOrWhiteSpace($DependencyDirectory)) {
    $DependencyDirectory = Join-Path $runtimeRoot '_deps'
}
$dependencyRoot = [System.IO.Path]::GetFullPath($DependencyDirectory)
if ([string]::IsNullOrWhiteSpace($OutputDirectory)) {
    $OutputDirectory = Join-Path $buildRoot 'windows-release'
}
$releaseRoot = [System.IO.Path]::GetFullPath($OutputDirectory)

function Assert-ChildPath {
    param([string] $Path, [string] $Parent, [string] $Description)

    $resolvedPath = [System.IO.Path]::GetFullPath($Path).TrimEnd('\')
    $resolvedParent = [System.IO.Path]::GetFullPath($Parent).TrimEnd('\') + '\'
    if (-not $resolvedPath.StartsWith(
        $resolvedParent,
        [System.StringComparison]::OrdinalIgnoreCase
    )) {
        throw "$Description must stay below $resolvedParent (received $resolvedPath)."
    }
}

Assert-ChildPath -Path $workingRoot -Parent $buildRoot -Description 'Installer working directory'
Assert-ChildPath -Path $cacheRoot -Parent $buildRoot -Description 'Installer cache directory'
Assert-ChildPath -Path $releaseRoot -Parent $buildRoot -Description 'Release output directory'

function Reset-BuildDirectory {
    param([string] $Path)

    Assert-ChildPath -Path $Path -Parent $buildRoot -Description 'Generated directory'
    if (Test-Path -LiteralPath $Path) {
        Remove-Item -LiteralPath $Path -Recurse -Force
    }
    New-Item -ItemType Directory -Path $Path -Force | Out-Null
}

function Get-VerifiedDownload {
    param(
        [string] $Uri,
        [string] $Path,
        [string] $ExpectedSha256
    )

    if (Test-Path -LiteralPath $Path -PathType Leaf) {
        $existingHash = (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash
        if ($existingHash -eq $ExpectedSha256) {
            return
        }
        throw "Cached artifact has unexpected SHA-256: $Path ($existingHash)."
    }

    $temporaryPath = $Path + '.' + [guid]::NewGuid().ToString('N') + '.download'
    try {
        Invoke-WebRequest -Uri $Uri -OutFile $temporaryPath
        $actualHash = (Get-FileHash -LiteralPath $temporaryPath -Algorithm SHA256).Hash
        if ($actualHash -ne $ExpectedSha256) {
            throw "SHA-256 mismatch for $Uri. Expected $ExpectedSha256, received $actualHash."
        }
        Move-Item -LiteralPath $temporaryPath -Destination $Path
    } finally {
        if (Test-Path -LiteralPath $temporaryPath) {
            Remove-Item -LiteralPath $temporaryPath -Force
        }
    }
}

function Copy-RequiredFile {
    param([string] $Source, [string] $Destination)

    if (-not (Test-Path -LiteralPath $Source -PathType Leaf)) {
        throw "Required file is missing: $Source"
    }
    Copy-Item -LiteralPath $Source -Destination $Destination -Force
}

function Invoke-Checked {
    param([string] $Executable, [string[]] $Arguments)

    & $Executable @Arguments
    if ($LASTEXITCODE -ne 0) {
        throw "$Executable failed with exit code $LASTEXITCODE."
    }
}

function Export-TarEntry {
    param([string] $Archive, [string] $Entry, [string] $Destination)

    $lines = & tar.exe -xOf $Archive $Entry
    if ($LASTEXITCODE -ne 0) {
        throw "Unable to extract $Entry from $Archive."
    }
    $lines | Set-Content -LiteralPath $Destination -Encoding utf8NoBOM
}

function Export-ZipEntry {
    param([string] $Archive, [string] $Entry, [string] $Destination)

    $zip = [System.IO.Compression.ZipFile]::OpenRead($Archive)
    try {
        $item = $zip.Entries | Where-Object { $_.FullName -eq $Entry } | Select-Object -First 1
        if ($null -eq $item) {
            throw "$Archive does not contain $Entry."
        }
        $inputStream = $item.Open()
        $outputStream = [System.IO.File]::Create($Destination)
        try {
            $inputStream.CopyTo($outputStream)
        } finally {
            $outputStream.Dispose()
            $inputStream.Dispose()
        }
    } finally {
        $zip.Dispose()
    }
}

function Find-SignTool {
    $command = Get-Command signtool.exe -ErrorAction SilentlyContinue
    if ($null -ne $command) {
        return $command.Source
    }
    $kitsRoot = 'C:\Program Files (x86)\Windows Kits\10\bin'
    $candidate = Get-ChildItem -LiteralPath $kitsRoot -Directory -ErrorAction SilentlyContinue |
        Sort-Object Name -Descending |
        ForEach-Object { Join-Path $_.FullName 'x64\signtool.exe' } |
        Where-Object { Test-Path -LiteralPath $_ -PathType Leaf } |
        Select-Object -First 1
    if ([string]::IsNullOrWhiteSpace($candidate)) {
        throw 'signtool.exe was not found in PATH or the Windows 10 SDK.'
    }
    return $candidate
}

function Sign-File {
    param([string] $Path, [string] $SignTool)

    Invoke-Checked -Executable $SignTool -Arguments @(
        'sign', '/fd', 'SHA256', '/sha1', $CertificateThumbprint,
        '/tr', $TimestampUrl, '/td', 'SHA256', $Path
    )
    $signature = Get-AuthenticodeSignature -LiteralPath $Path
    if ($signature.Status -ne [System.Management.Automation.SignatureStatus]::Valid) {
        throw "Authenticode validation failed after signing ${Path}: $($signature.Status)."
    }
}

if (-not (Test-Path -LiteralPath $runtimeRoot -PathType Container)) {
    throw "Runtime directory does not exist: $runtimeRoot"
}
if (-not (Test-Path -LiteralPath $dependencyRoot -PathType Container)) {
    throw "CMake dependency directory does not exist: $dependencyRoot"
}
if ([string]::IsNullOrWhiteSpace($LauncherPath)) {
    $LauncherPath = Join-Path $runtimeRoot 'sb-easy-setup.exe'
}
$LauncherPath = [System.IO.Path]::GetFullPath($LauncherPath)
if (-not (Test-Path -LiteralPath $LauncherPath -PathType Leaf)) {
    throw "Setup launcher is missing: $LauncherPath"
}

New-Item -ItemType Directory -Path $workingRoot, $cacheRoot -Force | Out-Null

$webViewUrl = 'https://msedge.sf.dl.delivery.mp.microsoft.com/filestreamingservice/files/bc30c82c-6362-4795-bb08-5351ad5a93bd/MicrosoftEdgeWebview2Setup.exe'
$webViewSha256 = 'E99838C51BB3379B244654AA77E33032D42FC2B5D224C5BABCE432D9FD3DCB28'
$webViewPath = Join-Path $cacheRoot 'MicrosoftEdgeWebview2Setup.exe'
Get-VerifiedDownload -Uri $webViewUrl -Path $webViewPath -ExpectedSha256 $webViewSha256
$webViewSignature = Get-AuthenticodeSignature -LiteralPath $webViewPath
if ($webViewSignature.Status -ne [System.Management.Automation.SignatureStatus]::Valid -or
    $webViewSignature.SignerCertificate.Subject -notmatch 'Microsoft Corporation') {
    throw 'The pinned WebView2 bootstrapper is not validly signed by Microsoft Corporation.'
}
if ((Get-Item -LiteralPath $webViewPath).VersionInfo.ProductVersion -ne '1.3.251.21') {
    throw 'The pinned WebView2 bootstrapper version is not 1.3.251.21.'
}

$singBoxSourceUrl = 'https://github.com/SagerNet/sing-box/archive/refs/tags/v1.13.12.tar.gz'
$singBoxSourceSha256 = '08F3F7295130B76A60C1CB6565B89DA6C4CE98D7BDEA8852973A5D2E3C6DE3B7'
$singBoxSourcePath = Join-Path $cacheRoot 'sing-box-1.13.12-source.tar.gz'
Get-VerifiedDownload -Uri $singBoxSourceUrl -Path $singBoxSourcePath -ExpectedSha256 $singBoxSourceSha256

$wixSourceUrl = 'https://github.com/wixtoolset/wix/archive/refs/tags/v5.0.2.tar.gz'
$wixSourceSha256 = '78C08FEA127A2219C916023DA90CC00780553088353702482D2942EAE57CA586'
$wixSourcePath = Join-Path $cacheRoot 'wix-5.0.2-source.tar.gz'
Get-VerifiedDownload -Uri $wixSourceUrl -Path $wixSourcePath -ExpectedSha256 $wixSourceSha256

$wintunUrl = 'https://www.wintun.net/builds/wintun-0.14.1.zip'
$wintunSha256 = '07C256185D6EE3652E09FA55C0B673E2624B565E02C4B9091C79CA7D2F24EF51'
$wintunArchivePath = Join-Path $cacheRoot 'wintun-0.14.1.zip'
Get-VerifiedDownload -Uri $wintunUrl -Path $wintunArchivePath -ExpectedSha256 $wintunSha256

$gplUrl = 'https://www.gnu.org/licenses/gpl-3.0.txt'
$gplSha256 = '3972DC9744F6499F0F9B2DBF76696F2AE7AD8AF9B23DDE66D6AF86C9DFB36986'
$gplPath = Join-Path $cacheRoot 'GPL-3.0.txt'
Get-VerifiedDownload -Uri $gplUrl -Path $gplPath -ExpectedSha256 $gplSha256

$payloadRoot = Join-Path $workingRoot 'payload'
$msiBuildRoot = Join-Path $workingRoot 'msi'
$bundleBuildRoot = Join-Path $workingRoot 'bundle'
Reset-BuildDirectory -Path $payloadRoot
Reset-BuildDirectory -Path $msiBuildRoot
Reset-BuildDirectory -Path $bundleBuildRoot
Reset-BuildDirectory -Path $releaseRoot

foreach ($name in @(
    'sb-easy.exe', 'sb-easy-service.exe', 'windows-runtime.json'
)) {
    Copy-RequiredFile -Source (Join-Path $runtimeRoot $name) -Destination (Join-Path $payloadRoot $name)
}
Copy-Item -LiteralPath (Join-Path $runtimeRoot 'ui') -Destination (Join-Path $payloadRoot 'ui') -Recurse

$runtimeMetadata = Get-Content -Raw (Join-Path $payloadRoot 'windows-runtime.json') | ConvertFrom-Json
if ($runtimeMetadata.sing_box.version -ne '1.13.12' -or
    $runtimeMetadata.sing_box.delivery -ne 'sb-easy-service-pe-resource' -or
    $runtimeMetadata.wintun.version -ne '0.14.1') {
    throw 'windows-runtime.json does not match the installer dependency pins.'
}
$wintunSignature = Get-AuthenticodeSignature -LiteralPath (Join-Path $runtimeRoot 'wintun.dll')
if ($wintunSignature.Status -ne [System.Management.Automation.SignatureStatus]::Valid) {
    throw 'The staged wintun.dll does not have a valid upstream Authenticode signature.'
}

$licensesRoot = Join-Path $payloadRoot 'licenses'
New-Item -ItemType Directory -Path $licensesRoot -Force | Out-Null
$licenseSourceRoot = Join-Path $repositoryRoot 'windows\installer\licenses'
foreach ($name in @(
    'THIRD-PARTY-NOTICES.txt', 'SQLite-PUBLIC-DOMAIN.txt',
    'WebView2-RUNTIME-NOTICE.txt'
)) {
    Copy-RequiredFile -Source (Join-Path $licenseSourceRoot $name) -Destination (Join-Path $licensesRoot $name)
}
Copy-RequiredFile -Source $gplPath -Destination (Join-Path $licensesRoot 'GPL-3.0.txt')
Export-TarEntry -Archive $singBoxSourcePath -Entry 'sing-box-1.13.12/LICENSE' -Destination (Join-Path $licensesRoot 'sing-box-LICENSE.txt')
Export-TarEntry -Archive $wixSourcePath -Entry 'wix-5.0.2/LICENSE.TXT' -Destination (Join-Path $licensesRoot 'WiX-MS-RL.txt')
Export-ZipEntry -Archive $wintunArchivePath -Entry 'wintun/LICENSE.txt' -Destination (Join-Path $licensesRoot 'Wintun-LICENSE.txt')

$webViewSdkRoot = Join-Path $dependencyRoot 'webview2_sdk-src'
$nlohmannRoot = Join-Path $dependencyRoot 'nlohmann_json-src'
$nodeModules = Join-Path $repositoryRoot 'windows\ui\node_modules'
Copy-RequiredFile -Source (Join-Path $webViewSdkRoot 'LICENSE.txt') -Destination (Join-Path $licensesRoot 'WebView2-SDK-LICENSE.txt')
Copy-RequiredFile -Source (Join-Path $webViewSdkRoot 'NOTICE.txt') -Destination (Join-Path $licensesRoot 'WebView2-SDK-NOTICE.txt')
Copy-RequiredFile -Source (Join-Path $nlohmannRoot 'LICENSE.MIT') -Destination (Join-Path $licensesRoot 'nlohmann-json-LICENSE.txt')
Copy-RequiredFile -Source (Join-Path $nodeModules 'vue\LICENSE') -Destination (Join-Path $licensesRoot 'Vue-LICENSE.txt')
Copy-RequiredFile -Source (Join-Path $nodeModules 'jsqr\LICENSE') -Destination (Join-Path $licensesRoot 'jsQR-LICENSE.txt')

$signTool = $null
if (-not [string]::IsNullOrWhiteSpace($CertificateThumbprint)) {
    $signTool = Find-SignTool
    Sign-File -Path (Join-Path $payloadRoot 'sb-easy.exe') -SignTool $signTool
    Sign-File -Path (Join-Path $payloadRoot 'sb-easy-service.exe') -SignTool $signTool
}

$msiProject = Join-Path $repositoryRoot 'windows\installer\msi\SbEasy.Msi.wixproj'
$msiOutputRoot = Join-Path $msiBuildRoot 'bin'
$msiObjectRoot = Join-Path $msiBuildRoot 'obj'
Invoke-Checked -Executable 'dotnet' -Arguments @(
    'build', $msiProject, '-c', 'Release',
    "-p:RuntimeDir=$payloadRoot", "-p:ProductVersion=$ProductVersion",
    "-p:BaseOutputPath=$msiOutputRoot\", "-p:BaseIntermediateOutputPath=$msiObjectRoot\"
)
$msiPath = Join-Path $msiOutputRoot 'x64\Release\sb-easy-windows-x64.msi'
if ($null -ne $signTool) {
    Sign-File -Path $msiPath -SignTool $signTool
}

$bundleProject = Join-Path $repositoryRoot 'windows\installer\bundle\SbEasy.Bundle.wixproj'
$bundleOutputRoot = Join-Path $bundleBuildRoot 'bin'
$bundleObjectRoot = Join-Path $bundleBuildRoot 'obj'
Invoke-Checked -Executable 'dotnet' -Arguments @(
    'build', $bundleProject, '-c', 'Release',
    '-p:OutputName=sb-easy-windows-bootstrapper',
    "-p:MsiPath=$msiPath", "-p:WebViewBootstrapperPath=$webViewPath",
    "-p:ProductVersion=$ProductVersion", "-p:BaseOutputPath=$bundleOutputRoot\",
    "-p:BaseIntermediateOutputPath=$bundleObjectRoot\"
)
$unsignedBundlePath = Join-Path $bundleOutputRoot 'x64\Release\sb-easy-windows-bootstrapper.exe'
$finalBundlePath = $unsignedBundlePath

$wixDll = Join-Path $env:USERPROFILE '.nuget\packages\wixtoolset.sdk\5.0.2\tools\net6.0\wix.dll'
if (-not (Test-Path -LiteralPath $wixDll -PathType Leaf)) {
    throw "Pinned WiX command-line assembly is missing: $wixDll"
}
if ($null -ne $signTool) {
    $enginePath = Join-Path $bundleBuildRoot 'sb-easy-burn-engine.exe'
    $reattachedPath = Join-Path $bundleBuildRoot 'sb-easy-windows-bootstrapper.signed-engine.exe'
    Invoke-Checked -Executable 'dotnet' -Arguments @($wixDll, 'burn', 'detach', $unsignedBundlePath, '-engine', $enginePath)
    Sign-File -Path $enginePath -SignTool $signTool
    Invoke-Checked -Executable 'dotnet' -Arguments @($wixDll, 'burn', 'reattach', $unsignedBundlePath, '-engine', $enginePath, '-o', $reattachedPath)
    Sign-File -Path $reattachedPath -SignTool $signTool
    $finalBundlePath = $reattachedPath
}

$releaseMsi = Join-Path $releaseRoot 'sb-easy-windows-x64.msi'
$releaseBundle = Join-Path $releaseRoot 'sb-easy-windows-bootstrapper.exe'
$releaseLauncher = Join-Path $releaseRoot 'sb-easy-windows-setup-x64.exe'
Copy-RequiredFile -Source $msiPath -Destination $releaseMsi
Copy-RequiredFile -Source $finalBundlePath -Destination $releaseBundle
Copy-RequiredFile -Source $LauncherPath -Destination $releaseLauncher
if ($null -ne $signTool) {
    Sign-File -Path $releaseLauncher -SignTool $signTool
}
Copy-RequiredFile -Source $singBoxSourcePath -Destination (Join-Path $releaseRoot 'sing-box-1.13.12-source.tar.gz')
Copy-RequiredFile -Source $wixSourcePath -Destination (Join-Path $releaseRoot 'wix-5.0.2-source.tar.gz')
Copy-Item -LiteralPath $licensesRoot -Destination (Join-Path $releaseRoot 'licenses') -Recurse

$sourceRevision = (& git -C $repositoryRoot rev-parse HEAD 2>$null)
$sourceDirty = [bool](& git -C $repositoryRoot status --porcelain 2>$null)
$releaseMetadata = [ordered]@{
    schema_version = 1
    product = 'sb-easy'
    product_version = $ProductVersion
    architecture = 'x64'
    source_revision = $sourceRevision
    source_worktree_dirty = $sourceDirty
    signed = ($null -ne $signTool)
    toolchain = [ordered]@{
        wix = '5.0.2'
        webview2_sdk = '1.0.4078.44'
        vue = '3.5.38'
        vite = '6.4.3'
        typescript = '5.7.3'
    }
    dependencies = [ordered]@{
        sing_box = [ordered]@{ version = '1.13.12'; source_sha256 = $singBoxSourceSha256 }
        wintun = [ordered]@{ version = '0.14.1'; archive_sha256 = $wintunSha256 }
        webview2_bootstrapper = [ordered]@{ version = '1.3.251.21'; sha256 = $webViewSha256 }
        wix = [ordered]@{ version = '5.0.2'; source_sha256 = $wixSourceSha256 }
    }
    artifacts = [ordered]@{
        setup_sha256 = (Get-FileHash -LiteralPath $releaseLauncher -Algorithm SHA256).Hash
        bootstrapper_sha256 = (Get-FileHash -LiteralPath $releaseBundle -Algorithm SHA256).Hash
        msi_sha256 = (Get-FileHash -LiteralPath $releaseMsi -Algorithm SHA256).Hash
        sing_box_archive_sha256 = $runtimeMetadata.sing_box.sha256
    }
}
$releaseMetadata | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath (
    Join-Path $releaseRoot 'windows-release-metadata.json'
) -Encoding utf8NoBOM

if ($null -eq $signTool) {
    @(
        'DEVELOPMENT BUILD - NOT SIGNED',
        'Do not publish this directory as a production release.',
        'Provide -CertificateThumbprint to build-windows-installer.ps1 for release signing.'
    ) | Set-Content -LiteralPath (Join-Path $releaseRoot 'DEVELOPMENT-UNSIGNED.txt') -Encoding utf8NoBOM
}

@(
    'sb-easy Windows installer',
    '',
    '1. Extract the entire sb-easy-windows-x64.zip archive to a folder.',
    '2. Keep sb-easy-windows-setup-x64.exe and sb-easy-windows-bootstrapper.exe together in that folder.',
    '3. Run sb-easy-windows-setup-x64.exe to install sb-easy.',
    '',
    'The setup executable is a launcher and requires the companion bootstrapper.',
    'Do not run it directly from the ZIP viewer or download only the launcher.',
    'The companion MSI supports managed deployment where WebView2 is already available.',
    '',
    'Version and signing details: windows-release-metadata.json.',
    'DEVELOPMENT-UNSIGNED.txt, when present, identifies an unsigned development build.',
    'Third-party notices, licenses, and corresponding source archives are included.',
    'Verify the ZIP using the SHA256SUMS published alongside the download.'
) | Set-Content -LiteralPath (Join-Path $releaseRoot 'README.txt') -Encoding utf8NoBOM

# Use an explicit input list so the archive never contains itself or the external
# checksum manifest. SHA256SUMS below includes the completed ZIP.
$installerArchiveNames = @(
    'sb-easy-windows-setup-x64.exe',
    'sb-easy-windows-bootstrapper.exe',
    'sb-easy-windows-x64.msi',
    'windows-release-metadata.json',
    'README.txt',
    'licenses',
    'sing-box-1.13.12-source.tar.gz',
    'wix-5.0.2-source.tar.gz'
)
if ($null -eq $signTool) {
    $installerArchiveNames += 'DEVELOPMENT-UNSIGNED.txt'
}
$installerArchivePaths = @($installerArchiveNames | ForEach-Object {
    Join-Path $releaseRoot $_
})
Compress-Archive -LiteralPath $installerArchivePaths -DestinationPath (
    Join-Path $releaseRoot 'sb-easy-windows-x64.zip'
) -CompressionLevel Optimal

$checksumLines = Get-ChildItem -LiteralPath $releaseRoot -Recurse -File |
    Where-Object { $_.Name -ne 'SHA256SUMS' } |
    Sort-Object FullName |
    ForEach-Object {
        $relative = [System.IO.Path]::GetRelativePath($releaseRoot, $_.FullName).Replace('\', '/')
        $hash = (Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
        "$hash  $relative"
    }
$checksumLines | Set-Content -LiteralPath (Join-Path $releaseRoot 'SHA256SUMS') -Encoding ascii

$validationScript = Join-Path $repositoryRoot 'scripts\test-windows-installer.ps1'
$validationArguments = @(
    '-NoProfile', '-File', $validationScript, '-ReleaseDirectory', $releaseRoot
)
if ($null -ne $signTool) {
    $validationArguments += '-RequireSigned'
}
Invoke-Checked -Executable (Join-Path $PSHOME 'pwsh.exe') -Arguments $validationArguments

Write-Host "Built Windows installer release assets in $releaseRoot"
if ($null -eq $signTool) {
    Write-Warning 'Artifacts are unsigned development outputs and are not production-ready.'
}
