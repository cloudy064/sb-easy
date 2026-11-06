[CmdletBinding()]
param(
    [string] $ReleaseDirectory,
    [switch] $RequireSigned
)

$ErrorActionPreference = 'Stop'

$repositoryRoot = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$buildRoot = [System.IO.Path]::GetFullPath((Join-Path $repositoryRoot 'build'))
if ([string]::IsNullOrWhiteSpace($ReleaseDirectory)) {
    $ReleaseDirectory = Join-Path $buildRoot 'windows-release'
}
$releaseRoot = [System.IO.Path]::GetFullPath($ReleaseDirectory)
$inspectionRoot = Join-Path $buildRoot 'windows-installer-validation'
$wixDll = Join-Path $env:USERPROFILE '.nuget\packages\wixtoolset.sdk\5.0.2\tools\net6.0\wix.dll'

function Assert-True {
    param([bool] $Value, [string] $Message)
    if (-not $Value) {
        throw $Message
    }
}

function Assert-Contains {
    param([string] $Text, [string] $Pattern, [string] $Description)
    if ($Text -notmatch $Pattern) {
        throw "Installer validation failed: $Description"
    }
}

function Invoke-Checked {
    param([string] $Executable, [string[]] $Arguments)
    & $Executable @Arguments
    if ($LASTEXITCODE -ne 0) {
        throw "$Executable failed with exit code $LASTEXITCODE."
    }
}

function ConvertTo-ProcessArgument {
    param([AllowEmptyString()][string] $Value)

    if ($Value.Length -gt 0 -and $Value -notmatch '[\s"]') {
        return $Value
    }
    # Start-Process joins ArgumentList with spaces. Escape embedded quotes and
    # trailing backslashes before adding quotes so paths with spaces survive.
    $escaped = [regex]::Replace($Value, '(\\*)"', '$1$1\"')
    $escaped = [regex]::Replace($escaped, '(\\+)$', '$1$1')
    return '"' + $escaped + '"'
}

function Invoke-LayoutSmoke {
    param(
        [string] $Executable,
        [string[]] $Arguments,
        [string] $LogPath,
        [ValidateRange(1, 60)]
        [int] $TimeoutSeconds = 60
    )

    $quotedArguments = @($Arguments | ForEach-Object { ConvertTo-ProcessArgument $_ })
    $process = Start-Process -FilePath $Executable -ArgumentList $quotedArguments `
        -WindowStyle Hidden -PassThru
    try {
        if (-not $process.WaitForExit($TimeoutSeconds * 1000)) {
            # Kill only the launcher started by this smoke test and its children;
            # never terminate another installer by process name.
            if (-not $process.HasExited) {
                $process.Kill($true)
                [void] $process.WaitForExit(5000)
            }
            $logDetail = if (Test-Path -LiteralPath $LogPath -PathType Leaf) {
                "See $LogPath."
            } else {
                "The bootstrapper did not create its log at $LogPath."
            }
            throw "Setup launcher timed out after $TimeoutSeconds seconds during the non-installing layout smoke test. $logDetail"
        }
        if ($process.ExitCode -ne 0) {
            throw "Setup launcher layout failed with exit code $($process.ExitCode). See $LogPath."
        }
    } finally {
        $process.Dispose()
    }
}

$inspectionFullPath = [System.IO.Path]::GetFullPath($inspectionRoot)
$buildPrefix = $buildRoot.TrimEnd('\') + '\'
Assert-True -Value $inspectionFullPath.StartsWith(
    $buildPrefix,
    [System.StringComparison]::OrdinalIgnoreCase
) -Message 'Inspection directory escaped the repository build directory.'

$msiPath = Join-Path $releaseRoot 'sb-easy-windows-x64.msi'
$launcherPath = Join-Path $releaseRoot 'sb-easy-windows-setup-x64.exe'
$bundlePath = Join-Path $releaseRoot 'sb-easy-windows-bootstrapper.exe'
$checksumPath = Join-Path $releaseRoot 'SHA256SUMS'
foreach ($path in @($msiPath, $launcherPath, $bundlePath, $checksumPath, $wixDll)) {
    Assert-True -Value (Test-Path -LiteralPath $path -PathType Leaf) -Message "Required validation input is missing: $path"
}
$launcherMagic = [System.IO.File]::ReadAllBytes($launcherPath)[0..1]
Assert-True -Value ($launcherMagic[0] -eq 0x4D -and $launcherMagic[1] -eq 0x5A) -Message 'The setup launcher is not a PE image.'

if (Test-Path -LiteralPath $inspectionFullPath) {
    Remove-Item -LiteralPath $inspectionFullPath -Recurse -Force
}
New-Item -ItemType Directory -Path $inspectionFullPath -Force | Out-Null

$decompiledPath = Join-Path $inspectionFullPath 'Product.decompiled.wxs'
$bundleExtractRoot = Join-Path $inspectionFullPath 'bundle'
$baExtractRoot = Join-Path $inspectionFullPath 'ba'
Invoke-Checked -Executable 'dotnet' -Arguments @(
    $wixDll, 'msi', 'decompile', $msiPath, '-o', $decompiledPath
)
Invoke-Checked -Executable 'dotnet' -Arguments @(
    $wixDll, 'burn', 'extract', $bundlePath,
    '-o', $bundleExtractRoot, '-oba', $baExtractRoot
)

$product = Get-Content -Raw -LiteralPath $decompiledPath
$manifestPath = Join-Path $baExtractRoot 'manifest.xml'
$baDataPath = Join-Path $baExtractRoot 'BootstrapperApplicationData.xml'
$themePath = Join-Path $repositoryRoot 'windows\installer\bundle\Theme.xml'
Assert-True -Value (Test-Path -LiteralPath $manifestPath -PathType Leaf) -Message 'Burn manifest was not extracted.'
Assert-True -Value (Test-Path -LiteralPath $baDataPath -PathType Leaf) -Message 'Bootstrapper application data was not extracted.'
Assert-True -Value (Test-Path -LiteralPath $themePath -PathType Leaf) -Message 'Bootstrapper theme source is missing.'
$manifest = Get-Content -Raw -LiteralPath $manifestPath
$baData = Get-Content -Raw -LiteralPath $baDataPath
$theme = Get-Content -Raw -LiteralPath $themePath

Assert-Contains $product 'ServiceInstall[^>]+Name="sb-easy"[^>]+Start="auto"' 'automatic sb-easy service registration is absent'
Assert-Contains $product 'ServiceControl[^>]+Start="install"[^>]+Stop="both"[^>]+Remove="uninstall"[^>]+Wait="yes"' 'synchronous service install/stop/remove control is absent'
Assert-Contains $product 'CustomAction[^>]+Id="ConfigureSbEasyService"[^>]+ExeCommand="--configure"' 'the checked SCM configuration action is absent'
Assert-Contains $product 'Custom[^>]+Action="ConfigureSbEasyService"[^>]+After="InstallServices"' 'the SCM configuration action is not sequenced after service creation'
Assert-Contains $product 'Software\\Classes\\sbeasy\\shell\\open\\command' 'the sbeasy protocol handler is absent'
Assert-Contains $product 'REMOVE_USER_DATA = 1' 'optional ProgramData cleanup is absent'
Assert-Contains $product 'INSTALL_STARTUP_SHORTCUT = 1' 'optional logon shortcut is absent'
Assert-Contains $product 'THIRD-PARTY-NOTICES.txt' 'third-party notices are absent from the MSI'
Assert-Contains $product 'MajorUpgrade' 'major upgrade handling is absent'
Assert-True -Value ($product -notmatch 'sing-box\.exe') `
    -Message 'The MSI installs sing-box.exe instead of embedding it in the Service.'
Assert-True -Value ($product -notmatch 'wintun\.dll') `
    -Message 'The MSI installs wintun.dll instead of embedding it in the Service.'

Assert-Contains $manifest 'Win64="yes"' 'the Burn engine is not x64'
Assert-Contains $manifest 'FindWebView2Machine' 'machine WebView2 detection is absent'
Assert-Contains $manifest 'FindWebView2User' 'per-user WebView2 detection is absent'
Assert-Contains $manifest 'F3017226-FE2A-4295-8BDF-00C3A9A7E4C5' 'the WebView2 runtime product identifier is absent'
Assert-Contains $manifest 'ExePackage Id="WebView2Evergreen"[^>]+Permanent="yes"' 'WebView2 is not modeled as a permanent prerequisite'
Assert-Contains $manifest 'DetectCondition="[^\"]*WebView2MachineVersion[^\"]*WebView2UserVersion' 'WebView2 conditional installation is absent'
Assert-Contains $manifest 'MsiProperty Id="INSTALL_STARTUP_SHORTCUT"' 'the bootstrapper does not pass the startup choice to MSI'
Assert-Contains $manifest 'MsiProperty Id="REMOVE_USER_DATA"' 'the bootstrapper does not pass the cleanup choice to MSI'
Assert-Contains $manifest 'Variable Id="InstallStartupShortcut"[^>]+Persisted="yes"' 'the startup choice is not retained for repair and maintenance'
Assert-Contains $manifest 'FilePath="thm\.xml"' 'the bootstrapper theme is not embedded in the UX container'
Assert-Contains $manifest 'FilePath="thm\.wxl"' 'the bootstrapper localization is not embedded in the UX container'
Assert-Contains $baData '<WixStdbaInformation(?:\s|>)' 'WixStdBA startup information is absent from BootstrapperApplicationData.xml'
Assert-Contains $baData '<WixStdbaOptions(?:\s|>)' 'WixStdBA options are absent from BootstrapperApplicationData.xml'
Assert-Contains $theme 'Checkbox Name="InstallStartupShortcut"' 'the startup choice is absent from setup UI'
Assert-Contains $theme 'Checkbox Name="RemoveUserData"' 'the data cleanup choice is absent from maintenance UI'

$embeddedWebView = Get-ChildItem -LiteralPath $bundleExtractRoot -Recurse -File |
    Where-Object { $_.Name -eq 'MicrosoftEdgeWebview2Setup.exe' } |
    Select-Object -First 1
$embeddedMsi = Get-ChildItem -LiteralPath $bundleExtractRoot -Recurse -File |
    Where-Object { $_.Name -eq 'sb-easy-windows-x64.msi' } |
    Select-Object -First 1
Assert-True -Value ($null -ne $embeddedWebView) -Message 'The WebView2 bootstrapper is not embedded in setup.'
Assert-True -Value ($null -ne $embeddedMsi) -Message 'The sb-easy MSI is not embedded in setup.'
$webViewSignature = Get-AuthenticodeSignature -LiteralPath $embeddedWebView.FullName
Assert-True -Value (
    $webViewSignature.Status -eq [System.Management.Automation.SignatureStatus]::Valid -and
    $webViewSignature.SignerCertificate.Subject -match 'Microsoft Corporation'
) -Message 'The embedded WebView2 bootstrapper is not validly signed by Microsoft.'

# A Burn layout runs the real bootstrapper application startup path but never
# executes package installation. This catches malformed BA metadata that a
# container-only inspection cannot detect. The layout is driven through the
# shipped setup launcher, which places the extracted bootstrapper application
# outside the caller's temporary directory: Windows runs temporary images at low
# integrity, and a low-integrity bootstrapper application cannot open the
# engine's medium-integrity pipe, which hangs setup with ERROR_TIMEOUT.
$layoutRoot = Join-Path $inspectionFullPath 'layout-smoke'
$layoutLog = Join-Path $inspectionFullPath 'layout-smoke.log'
$serviceBefore = [bool](Get-Service -Name 'sb-easy' -ErrorAction SilentlyContinue)
$protocolKey = 'Registry::HKEY_LOCAL_MACHINE\Software\Classes\sbeasy'
$protocolBefore = [bool](Get-Item -LiteralPath $protocolKey -ErrorAction SilentlyContinue)
$processesBefore = @(
    Get-Process -Name 'sb-easy', 'sb-easy-service', 'sing-box' -ErrorAction SilentlyContinue |
        ForEach-Object { "$($_.ProcessName)|$($_.Id)" } |
        Sort-Object
) -join "`n"
Invoke-LayoutSmoke -Executable $launcherPath -LogPath $layoutLog -Arguments @(
    '/layout', $layoutRoot, '/quiet', '/norestart', '/log', $layoutLog
)
$layoutBundle = Join-Path $layoutRoot 'sb-easy-windows-bootstrapper.exe'
$layoutDeadline = [DateTime]::UtcNow.AddSeconds(30)
do {
    $layoutFinished = (Test-Path -LiteralPath $layoutBundle -PathType Leaf) -and
        (Test-Path -LiteralPath $layoutLog -PathType Leaf) -and
        ((Get-Content -Raw -LiteralPath $layoutLog) -match
            '(?m)i007: Exit code: 0x0, restarting: No')
    if (-not $layoutFinished) {
        Start-Sleep -Milliseconds 100
    }
} while (-not $layoutFinished -and [DateTime]::UtcNow -lt $layoutDeadline)
Assert-True -Value (Test-Path -LiteralPath $layoutBundle -PathType Leaf) `
    -Message 'Burn layout did not copy the compressed bundle.'
Assert-True -Value (
    (Get-FileHash -LiteralPath $layoutBundle -Algorithm SHA256).Hash -eq
    (Get-FileHash -LiteralPath $bundlePath -Algorithm SHA256).Hash
) -Message 'Burn layout bundle does not match its source.'
$layoutLogContents = Get-Content -Raw -LiteralPath $layoutLog
Assert-Contains $layoutLogContents 'WixStdBALanguageId' 'WixStdBA did not initialize during the layout smoke test'
Assert-Contains $layoutLogContents 'i199: Detect complete, result: 0x0' 'Burn detection did not complete during the layout smoke test'
Assert-Contains $layoutLogContents 'i299: Plan complete, result: 0x0' 'Burn planning did not complete during the layout smoke test'
Assert-Contains $layoutLogContents 'i399: Apply complete, result: 0x0' 'Burn layout did not complete successfully'
Assert-Contains $layoutLogContents 'i007: Exit code: 0x0, restarting: No' 'Burn layout did not exit successfully'
Assert-True -Value ($layoutLogContents -notmatch '(?m)\]e\d{3}:') `
    -Message "Burn layout startup logged an error. See $layoutLog"
$serviceAfter = [bool](Get-Service -Name 'sb-easy' -ErrorAction SilentlyContinue)
$protocolAfter = [bool](Get-Item -LiteralPath $protocolKey -ErrorAction SilentlyContinue)
$processesAfter = @(
    Get-Process -Name 'sb-easy', 'sb-easy-service', 'sing-box' -ErrorAction SilentlyContinue |
        ForEach-Object { "$($_.ProcessName)|$($_.Id)" } |
        Sort-Object
) -join "`n"
Assert-True -Value ($serviceAfter -eq $serviceBefore) `
    -Message 'Burn layout unexpectedly changed service registration.'
Assert-True -Value ($protocolAfter -eq $protocolBefore) `
    -Message 'Burn layout unexpectedly changed protocol registration.'
Assert-True -Value ($processesAfter -eq $processesBefore) `
    -Message 'Burn layout unexpectedly changed product process state.'

foreach ($line in Get-Content -LiteralPath $checksumPath) {
    if ([string]::IsNullOrWhiteSpace($line)) {
        continue
    }
    $parts = $line -split '\s{2}', 2
    Assert-True -Value ($parts.Count -eq 2) -Message "Malformed SHA256SUMS line: $line"
    $artifactPath = Join-Path $releaseRoot $parts[1].Replace('/', '\')
    Assert-True -Value (Test-Path -LiteralPath $artifactPath -PathType Leaf) -Message "Checksummed file is missing: $($parts[1])"
    $actualHash = (Get-FileHash -LiteralPath $artifactPath -Algorithm SHA256).Hash.ToLowerInvariant()
    Assert-True -Value ($actualHash -eq $parts[0]) -Message "Checksum mismatch: $($parts[1])"
}

Assert-True -Value (
    (Get-FileHash -LiteralPath (Join-Path $releaseRoot 'sing-box-1.13.12-source.tar.gz') -Algorithm SHA256).Hash -eq
    '08F3F7295130B76A60C1CB6565B89DA6C4CE98D7BDEA8852973A5D2E3C6DE3B7'
) -Message 'The published sing-box source archive does not match its pin.'
Assert-True -Value (
    (Get-FileHash -LiteralPath (Join-Path $releaseRoot 'wix-5.0.2-source.tar.gz') -Algorithm SHA256).Hash -eq
    '78C08FEA127A2219C916023DA90CC00780553088353702482D2942EAE57CA586'
) -Message 'The published WiX source archive does not match its pin.'

if ($RequireSigned) {
    foreach ($path in @($msiPath, $launcherPath, $bundlePath)) {
        $signature = Get-AuthenticodeSignature -LiteralPath $path
        Assert-True -Value (
            $signature.Status -eq [System.Management.Automation.SignatureStatus]::Valid
        ) -Message "Release artifact is not validly signed: $path"
    }
} else {
    Assert-True -Value (
        Test-Path -LiteralPath (Join-Path $releaseRoot 'DEVELOPMENT-UNSIGNED.txt') -PathType Leaf
    ) -Message 'Unsigned artifacts are missing the development-only marker.'
}

Write-Host 'Windows installer static and Burn startup/layout validation passed without installing or registering anything.'
