$ErrorActionPreference = 'Stop'
$repo = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
function Expect-Failure([scriptblock]$Action, [string]$Pattern) {
    try { & $Action; throw 'UNEXPECTED_SUCCESS' } catch { if ($_.Exception.Message -eq 'UNEXPECTED_SUCCESS' -or $_.Exception.Message -notmatch $Pattern) { throw } }
}
Expect-Failure { & "$repo/windows/scripts/package.ps1" -TrustedRelease } 'Trusted release requires'
Expect-Failure { & "$repo/windows/scripts/package-msi.ps1" -Payload '.' -Version '00.7.0' } 'canonical'
Expect-Failure { & "$repo/windows/scripts/package-msi.ps1" -Payload '.' -Version '256.0.0' } 'Installer limits'
Expect-Failure { & "$repo/windows/scripts/write-release-manifest.ps1" -Artifacts @('absent.msi') -Output 'absent.json' -Version '0.7.0' -MinimumAppVersion '0.8.0' -CertificateThumbprint ('A' * 40) } 'cannot exceed'
if (-not $IsWindows) { Expect-Failure { & "$repo/windows/scripts/sign-release.ps1" -Files @('absent.exe') -CertificateThumbprint ('A' * 40) -TimestampUrl https://timestamp.example.test } 'requires Windows' }
Add-Type -AssemblyName System.Security.Cryptography.Pkcs
$testRoot = Join-Path ([IO.Path]::GetTempPath()) ('sb-easy-release-verify-' + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $testRoot > $null
$key = [System.Security.Cryptography.RSA]::Create(2048)
try {
    $request = [System.Security.Cryptography.X509Certificates.CertificateRequest]::new('CN=sb-easy Untrusted Test Only', $key, [System.Security.Cryptography.HashAlgorithmName]::SHA256, [System.Security.Cryptography.RSASignaturePadding]::Pkcs1)
    $certificate = $request.CreateSelfSigned([DateTimeOffset]::UtcNow.AddMinutes(-1), [DateTimeOffset]::UtcNow.AddDays(1))
    $path = Join-Path $testRoot 'release.json'
    $bytes = [Text.Encoding]::UTF8.GetBytes('{"schema":1,"files":[]}')
    $cms = [System.Security.Cryptography.Pkcs.SignedCms]::new([System.Security.Cryptography.Pkcs.ContentInfo]::new($bytes), $true)
    $cms.ComputeSignature([System.Security.Cryptography.Pkcs.CmsSigner]::new($certificate))
    [IO.File]::WriteAllBytes($path, $bytes)
    [IO.File]::WriteAllBytes($path + '.p7s', $cms.Encode())
    Expect-Failure { & "$repo/windows/scripts/verify-release.ps1" -Manifest $path -CertificateThumbprint ('A' * 40) } 'expected publisher'
    Expect-Failure { & "$repo/windows/scripts/verify-release.ps1" -Manifest $path -CertificateThumbprint $certificate.Thumbprint } 'certificate|trust|chain'
    [IO.File]::WriteAllText($path, '{"schema":1,"files":["tampered"]}')
    Expect-Failure { & "$repo/windows/scripts/verify-release.ps1" -Manifest $path -CertificateThumbprint $certificate.Thumbprint } 'hash|signature'
    Write-Output 'Release guard tests passed: missing release credentials, wrong publisher, untrusted signer and tampered CMS content are rejected; no certificate was trusted or installed.'
} finally { $key.Dispose(); Remove-Item -LiteralPath $testRoot -Recurse -Force }
