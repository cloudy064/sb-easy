[CmdletBinding()]
param(
    [string] $ReleaseDirectory
)

$ErrorActionPreference = 'Stop'

$repositoryRoot = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$buildRoot = [System.IO.Path]::GetFullPath((Join-Path $repositoryRoot 'build'))
if ([string]::IsNullOrWhiteSpace($ReleaseDirectory)) {
    $ReleaseDirectory = Join-Path $buildRoot 'windows-release'
}
$releaseRoot = [System.IO.Path]::GetFullPath($ReleaseDirectory)
$inspectionRoot = [System.IO.Path]::GetFullPath((
    Join-Path $buildRoot 'windows-installer-admin-image'
))
$logPath = Join-Path $inspectionRoot 'administrative-install.log'
$msiPath = Join-Path $releaseRoot 'sb-easy-windows-x64.msi'

function Assert-True {
    param([bool] $Value, [string] $Message)
    if (-not $Value) {
        throw $Message
    }
}

$buildPrefix = $buildRoot.TrimEnd('\') + '\'
Assert-True -Value $inspectionRoot.StartsWith(
    $buildPrefix,
    [System.StringComparison]::OrdinalIgnoreCase
) -Message 'Administrative image directory escaped the repository build directory.'
Assert-True -Value (Test-Path -LiteralPath $msiPath -PathType Leaf) `
    -Message "MSI is missing: $msiPath"

$serviceBefore = [bool](Get-Service -Name 'sb-easy' -ErrorAction SilentlyContinue)
$protocolKey = 'Registry::HKEY_LOCAL_MACHINE\Software\Classes\sbeasy'
$protocolBefore = [bool](Get-Item -LiteralPath $protocolKey -ErrorAction SilentlyContinue)
$processesBefore = @(
    Get-Process -Name 'sb-easy', 'sb-easy-service', 'sing-box' -ErrorAction SilentlyContinue |
        ForEach-Object { "$($_.ProcessName)|$($_.Id)" } |
        Sort-Object
)
$processFingerprintBefore = $processesBefore -join "`n"

if (Test-Path -LiteralPath $inspectionRoot) {
    Remove-Item -LiteralPath $inspectionRoot -Recurse -Force
}
New-Item -ItemType Directory -Path $inspectionRoot | Out-Null

$arguments = @(
    '/a', ('"' + $msiPath + '"'),
    ('TARGETDIR="' + $inspectionRoot + '"'),
    '/qn', '/norestart', '/l*v', ('"' + $logPath + '"')
)
$process = Start-Process -FilePath 'msiexec.exe' -ArgumentList $arguments `
    -WindowStyle Hidden -Wait -PassThru
if ($process.ExitCode -notin @(0, 3010)) {
    throw "MSI administrative image failed with exit code $($process.ExitCode). See $logPath."
}

$expectedFiles = @(
    'PFiles64\sb-easy\sb-easy.exe',
    'PFiles64\sb-easy\sb-easy-service.exe',
    'PFiles64\sb-easy\windows-runtime.json',
    'PFiles64\sb-easy\ui\index.html',
    'PFiles64\sb-easy\ui\assets\app.js',
    'PFiles64\sb-easy\ui\assets\app.css',
    'PFiles64\sb-easy\licenses\THIRD-PARTY-NOTICES.txt',
    'PFiles64\sb-easy\licenses\GPL-3.0.txt',
    'PFiles64\sb-easy\licenses\Wintun-LICENSE.txt',
    'PFiles64\sb-easy\licenses\WiX-MS-RL.txt'
)
foreach ($relativePath in $expectedFiles) {
    $path = Join-Path $inspectionRoot $relativePath
    Assert-True -Value (Test-Path -LiteralPath $path -PathType Leaf) `
        -Message "Administrative image payload is missing: $relativePath"
    Assert-True -Value ((Get-Item -LiteralPath $path).Length -gt 0) `
        -Message "Administrative image payload is empty: $relativePath"
}
$installedRoot = Join-Path $inspectionRoot 'PFiles64\sb-easy'
$runtimeMetadata = Get-Content -Raw -LiteralPath (
    Join-Path $installedRoot 'windows-runtime.json'
) | ConvertFrom-Json
Assert-True -Value ($runtimeMetadata.sing_box.version -eq '1.13.12') `
    -Message 'Runtime metadata does not identify the pinned sing-box version.'
Assert-True -Value ($runtimeMetadata.sing_box.delivery -eq 'sb-easy-service-pe-resource') `
    -Message 'Runtime metadata does not identify the embedded PE-resource delivery.'
Assert-True -Value (-not (Test-Path -LiteralPath (
    Join-Path $installedRoot 'sing-box.exe'
) -PathType Leaf)) -Message 'MSI must not install sing-box.exe as a separate component.'
Assert-True -Value (-not (Test-Path -LiteralPath (
    Join-Path $installedRoot 'wintun.dll'
) -PathType Leaf)) -Message 'MSI must not install wintun.dll as a separate component.'

$serviceAfter = [bool](Get-Service -Name 'sb-easy' -ErrorAction SilentlyContinue)
$protocolAfter = [bool](Get-Item -LiteralPath $protocolKey -ErrorAction SilentlyContinue)
$processesAfter = @(
    Get-Process -Name 'sb-easy', 'sb-easy-service', 'sing-box' -ErrorAction SilentlyContinue |
        ForEach-Object { "$($_.ProcessName)|$($_.Id)" } |
        Sort-Object
)
$processFingerprintAfter = $processesAfter -join "`n"
Assert-True -Value ($serviceAfter -eq $serviceBefore) `
    -Message 'Administrative image unexpectedly changed sb-easy service registration.'
Assert-True -Value ($protocolAfter -eq $protocolBefore) `
    -Message 'Administrative image unexpectedly changed sbeasy protocol registration.'
Assert-True -Value ($processFingerprintAfter -eq $processFingerprintBefore) `
    -Message 'Administrative image unexpectedly changed sb-easy process state.'

Write-Host (
    "MSI administrative image contains {0} required payload files and did not execute product installation." -f
    $expectedFiles.Count
)
