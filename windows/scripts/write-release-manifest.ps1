param(
    [Parameter(Mandatory)][string[]]$Artifacts,
    [Parameter(Mandatory)][string]$Output,
    [Parameter(Mandatory)][ValidatePattern('^[A-Fa-f0-9]{40}$')][string]$CertificateThumbprint,
    [Parameter(Mandatory)][ValidatePattern('^\d+\.\d+\.\d+$')][string]$Version,
    [ValidatePattern('^\d+\.\d+\.\d+$')][string]$MinimumAppVersion = '0.7.0',
    [ValidateRange(0,100)][int]$RolloutPercent = 100
)
$ErrorActionPreference = 'Stop'
if ([version]$MinimumAppVersion -gt [version]$Version) { throw 'MinimumAppVersion cannot exceed the release version.' }
if (-not $IsWindows) { throw 'Release manifests require the Windows publisher certificate store.' }
Add-Type -AssemblyName System.Security.Cryptography.Pkcs
$certificate = Get-Item -LiteralPath "Cert:\CurrentUser\My\$CertificateThumbprint" -ErrorAction Stop
if (-not $certificate.HasPrivateKey) { throw 'The release publisher private key is unavailable.' }
$outputPath = [IO.Path]::GetFullPath($Output)
$outputDirectory = Split-Path -Parent $outputPath
if (-not (Test-Path -LiteralPath $outputDirectory -PathType Container)) { throw 'The release output directory must already exist.' }
$seen = @{}
$files = foreach ($artifact in $Artifacts) {
    $file = Get-Item -LiteralPath $artifact -ErrorAction Stop
    if ($file.PSIsContainer -or ($file.Attributes -band [IO.FileAttributes]::ReparsePoint) -or $file.DirectoryName -ne $outputDirectory -or $file.Extension -notin @('.zip', '.msi') -or $seen.ContainsKey($file.Name)) { throw 'Release artifacts must be unique regular ZIP/MSI files beside the manifest.' }
    $seen[$file.Name] = $true
    if ($file.Extension -eq '.msi') {
        $signature = Get-AuthenticodeSignature -LiteralPath $file.FullName
        if ($signature.Status -ne 'Valid' -or $signature.SignerCertificate.Thumbprint -ne $CertificateThumbprint -or -not $signature.TimeStamperCertificate) { throw 'The installer must have a verified timestamped publisher signature.' }
    }
    [ordered]@{ name = $file.Name; bytes = $file.Length; sha256 = (Get-FileHash -LiteralPath $file.FullName -Algorithm SHA256).Hash.ToLowerInvariant() }
}
if ($seen.Count -lt 1 -or $seen.Count -gt 4 -or @($files | Where-Object { $_.name.EndsWith('.msi') }).Count -ne 1) { throw 'Release manifests contain 1 to 4 artifacts and exactly one MSI.' }
$runtime = Get-Content -LiteralPath (Join-Path $PSScriptRoot '../../config/runtime-versions.json') -Raw | ConvertFrom-Json
$manifest = [ordered]@{ schema = 2; version = $Version; created_at = [DateTime]::UtcNow.ToString('o'); publisher_thumbprint = $CertificateThumbprint.ToUpperInvariant(); platform = 'windows'; architecture = 'x64'; core_version = $runtime.sing_box.version; minimum_app_version = $MinimumAppVersion; protocol_version = 1; channel = 'stable'; rollout_percent = $RolloutPercent; files = @($files) }
$json = $manifest | ConvertTo-Json -Depth 5
$bytes = [Text.UTF8Encoding]::new($false).GetBytes($json)
$cms = [System.Security.Cryptography.Pkcs.SignedCms]::new([System.Security.Cryptography.Pkcs.ContentInfo]::new($bytes), $true)
$signer = [System.Security.Cryptography.Pkcs.CmsSigner]::new($certificate)
$signer.IncludeOption = [System.Security.Cryptography.X509Certificates.X509IncludeOption]::ExcludeRoot
$signer.DigestAlgorithm = [System.Security.Cryptography.Oid]::new('2.16.840.1.101.3.4.2.1')
$cms.ComputeSignature($signer, $false)
$cms.CheckSignature($false)
[IO.File]::WriteAllBytes($outputPath, $bytes)
[IO.File]::WriteAllBytes($outputPath + '.p7s', $cms.Encode())
& (Join-Path $PSScriptRoot 'verify-release.ps1') -Manifest $outputPath -CertificateThumbprint $CertificateThumbprint
