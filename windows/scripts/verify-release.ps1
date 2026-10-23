param(
    [Parameter(Mandatory)][string]$Manifest,
    [Parameter(Mandatory)][ValidatePattern('^[A-Fa-f0-9]{40}$')][string]$CertificateThumbprint
)
$ErrorActionPreference = 'Stop'
# The expected thumbprint must come from a trusted publisher channel. Never
# accept the unverified manifest's publisher field as its own trust anchor.
Add-Type -AssemblyName System.Security.Cryptography.Pkcs
$manifestFile = Get-Item -LiteralPath $Manifest -ErrorAction Stop
if ($manifestFile.PSIsContainer -or $manifestFile.Length -gt 65536 -or ($manifestFile.Attributes -band [IO.FileAttributes]::ReparsePoint)) { throw 'Invalid release manifest file.' }
$signatureFile = Get-Item -LiteralPath ($manifestFile.FullName + '.p7s') -ErrorAction Stop
if ($signatureFile.PSIsContainer -or $signatureFile.Length -gt 262144 -or ($signatureFile.Attributes -band [IO.FileAttributes]::ReparsePoint)) { throw 'Invalid detached release signature.' }
$bytes = [IO.File]::ReadAllBytes($manifestFile.FullName)
$cms = [System.Security.Cryptography.Pkcs.SignedCms]::new([System.Security.Cryptography.Pkcs.ContentInfo]::new($bytes), $true)
$cms.Decode([IO.File]::ReadAllBytes($signatureFile.FullName))
if ($cms.SignerInfos.Count -ne 1 -or $cms.SignerInfos[0].Certificate.Thumbprint -ne $CertificateThumbprint) { throw 'The release manifest is not signed by the expected publisher.' }
$cms.CheckSignature($false)
if ($cms.SignerInfos[0].DigestAlgorithm.Value -ne '2.16.840.1.101.3.4.2.1') { throw 'Release manifests require a SHA-256 signature.' }
$manifestData = [Text.Encoding]::UTF8.GetString($bytes) | ConvertFrom-Json
if ($manifestData.schema -ne 2 -or $manifestData.publisher_thumbprint -ne $CertificateThumbprint -or @($manifestData.files).Count -lt 1 -or @($manifestData.files).Count -gt 4 -or $manifestData.platform -ne 'windows' -or $manifestData.architecture -ne 'x64' -or $manifestData.channel -ne 'stable' -or $manifestData.protocol_version -ne 1 -or $manifestData.version -notmatch '^\d+\.\d+\.\d+$' -or $manifestData.core_version -notmatch '^\d+\.\d+\.\d+$' -or $manifestData.minimum_app_version -notmatch '^\d+\.\d+\.\d+$' -or $manifestData.rollout_percent -lt 0 -or $manifestData.rollout_percent -gt 100 -or @($manifestData.files | Where-Object { $_.name.EndsWith('.msi') }).Count -ne 1) { throw 'Invalid signed release manifest schema.' }
$seen = @{}
foreach ($entry in $manifestData.files) {
    if ($entry.name -notmatch '^[A-Za-z0-9][A-Za-z0-9._-]{0,154}\.(zip|msi)$' -or $entry.name.Contains('..') -or $entry.sha256 -notmatch '^[a-fA-F0-9]{64}$' -or $entry.bytes -isnot [long] -and $entry.bytes -isnot [int] -or $entry.bytes -le 0 -or $entry.bytes -gt 536870912 -or $seen.ContainsKey($entry.name)) { throw 'Invalid signed release artifact entry.' }
    $seen[$entry.name] = $true
    $file = Get-Item -LiteralPath (Join-Path $manifestFile.DirectoryName $entry.name) -ErrorAction Stop
    if ($file.PSIsContainer -or ($file.Attributes -band [IO.FileAttributes]::ReparsePoint) -or $file.Length -ne $entry.bytes -or (Get-FileHash -LiteralPath $file.FullName -Algorithm SHA256).Hash -ne $entry.sha256) { throw "Release artifact integrity failed: $($entry.name)" }
    if ($IsWindows -and $file.Extension -eq '.msi') {
        $signature = Get-AuthenticodeSignature -LiteralPath $file.FullName
        if ($signature.Status -ne 'Valid' -or $signature.SignerCertificate.Thumbprint -ne $CertificateThumbprint -or -not $signature.TimeStamperCertificate) { throw 'The installer publisher or timestamp could not be verified.' }
    }
    Write-Output "Verified release artifact: $($entry.name)"
}
