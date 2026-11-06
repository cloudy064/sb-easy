[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string] $Destination
)

$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

$singBoxVersion = '1.13.12'
$singBoxArchiveName = "sing-box-$singBoxVersion-windows-amd64.zip"
$singBoxUrl = "https://github.com/SagerNet/sing-box/releases/download/v$singBoxVersion/$singBoxArchiveName"
$singBoxSha256 = 'e93fc531134eb1beb4efa3c74990a24e48456098a31c03b60d5ddf17f223cf98'

$wintunVersion = '0.14.1'
$wintunArchiveName = "wintun-$wintunVersion.zip"
$wintunUrl = "https://www.wintun.net/builds/$wintunArchiveName"
$wintunSha256 = '07c256185d6ee3652e09fa55c0b673e2624b565e02c4b9091c79ca7d2f24ef51'

function Get-VerifiedArchive {
    param(
        [string] $Uri,
        [string] $Path,
        [string] $ExpectedSha256
    )

    Invoke-WebRequest -Uri $Uri -OutFile $Path
    $actual = (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($actual -ne $ExpectedSha256) {
        throw "SHA-256 mismatch for $Uri. Expected $ExpectedSha256, received $actual."
    }
}

$destinationPath = [System.IO.Path]::GetFullPath($Destination)
New-Item -ItemType Directory -Path $destinationPath -Force | Out-Null
$temporaryRoot = Join-Path ([System.IO.Path]::GetTempPath()) (
    'sb-easy-windows-runtime-' + [guid]::NewGuid().ToString('N')
)
New-Item -ItemType Directory -Path $temporaryRoot | Out-Null

try {
    $singBoxArchive = Join-Path $temporaryRoot $singBoxArchiveName
    $wintunArchive = Join-Path $temporaryRoot $wintunArchiveName
    Get-VerifiedArchive -Uri $singBoxUrl -Path $singBoxArchive `
        -ExpectedSha256 $singBoxSha256
    Get-VerifiedArchive -Uri $wintunUrl -Path $wintunArchive `
        -ExpectedSha256 $wintunSha256

    $singBoxExtract = Join-Path $temporaryRoot 'sing-box'
    $wintunExtract = Join-Path $temporaryRoot 'wintun'
    Expand-Archive -LiteralPath $singBoxArchive -DestinationPath $singBoxExtract
    Expand-Archive -LiteralPath $wintunArchive -DestinationPath $wintunExtract

    $singBoxExecutable = Get-ChildItem -LiteralPath $singBoxExtract `
        -Filter 'sing-box.exe' -File -Recurse | Select-Object -First 1
    if ($null -eq $singBoxExecutable) {
        throw 'Pinned sing-box archive does not contain sing-box.exe.'
    }
    $wintunDll = Join-Path $wintunExtract 'wintun\bin\amd64\wintun.dll'
    if (-not (Test-Path -LiteralPath $wintunDll -PathType Leaf)) {
        throw 'Pinned Wintun archive does not contain the AMD64 wintun.dll.'
    }
    $signature = Get-AuthenticodeSignature -LiteralPath $wintunDll
    if ($signature.Status -ne [System.Management.Automation.SignatureStatus]::Valid) {
        throw "Pinned wintun.dll has an invalid Authenticode signature: $($signature.Status)."
    }

    Copy-Item -LiteralPath $singBoxExecutable.FullName -Destination (
        Join-Path $destinationPath 'sing-box.exe'
    ) -Force
    Copy-Item -LiteralPath $wintunDll -Destination (
        Join-Path $destinationPath 'wintun.dll'
    ) -Force
    $obsoleteCore = Join-Path $destinationPath 'sb-easy-core.dll'
    if (Test-Path -LiteralPath $obsoleteCore -PathType Leaf) {
        Remove-Item -LiteralPath $obsoleteCore -Force
    }

    $metadata = [ordered]@{
        sing_box = [ordered]@{
            version = $singBoxVersion
            delivery = 'sb-easy-service-pe-resource'
            archive = $singBoxArchiveName
            sha256 = $singBoxSha256
            binary_sha256 = (Get-FileHash -LiteralPath (
                Join-Path $destinationPath 'sing-box.exe'
            ) -Algorithm SHA256).Hash.ToLowerInvariant()
            source = $singBoxUrl
        }
        wintun = [ordered]@{
            version = $wintunVersion
            archive = $wintunArchiveName
            sha256 = $wintunSha256
            binary_sha256 = (Get-FileHash -LiteralPath (
                Join-Path $destinationPath 'wintun.dll'
            ) -Algorithm SHA256).Hash.ToLowerInvariant()
            source = $wintunUrl
            authenticode_subject = $signature.SignerCertificate.Subject
            authenticode_thumbprint = $signature.SignerCertificate.Thumbprint
        }
    }
    $metadata | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath (
        Join-Path $destinationPath 'windows-runtime.json'
    ) -Encoding utf8NoBOM
} finally {
    $resolvedTemporary = [System.IO.Path]::GetFullPath($temporaryRoot)
    $temporaryBase = [System.IO.Path]::GetFullPath([System.IO.Path]::GetTempPath())
    if ($resolvedTemporary.StartsWith(
        $temporaryBase,
        [System.StringComparison]::OrdinalIgnoreCase
    )) {
        Remove-Item -LiteralPath $resolvedTemporary -Recurse -Force
    }
}

Write-Host "Prepared pinned Windows runtime in $destinationPath"
