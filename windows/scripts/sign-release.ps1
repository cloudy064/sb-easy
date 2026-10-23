param(
    [Parameter(Mandatory)][string[]]$Files,
    [Parameter(Mandatory)][ValidatePattern('^[A-Fa-f0-9]{40}$')][string]$CertificateThumbprint,
    [Parameter(Mandatory)][uri]$TimestampUrl,
    [string]$SignToolPath = 'signtool.exe'
)
$ErrorActionPreference = 'Stop'
if (-not $IsWindows) { throw 'Authenticode release signing requires Windows.' }
if ($TimestampUrl.Scheme -notin @('http', 'https') -or $TimestampUrl.UserInfo -or $TimestampUrl.Fragment) { throw 'Use a credential-free HTTP(S) RFC3161 timestamp endpoint.' }
$certificate = Get-Item -LiteralPath "Cert:\CurrentUser\My\$CertificateThumbprint" -ErrorAction Stop
if (-not $certificate.HasPrivateKey -or $certificate.NotBefore -gt [DateTime]::Now -or $certificate.NotAfter -le [DateTime]::Now) { throw 'The signing certificate needs a usable private key and a current validity period.' }
if (-not ($certificate.EnhancedKeyUsageList | Where-Object { $_.ObjectId.Value -eq '1.3.6.1.5.5.7.3.3' })) { throw 'The certificate must explicitly permit code signing.' }
$chain = [System.Security.Cryptography.X509Certificates.X509Chain]::new()
try {
    $chain.ChainPolicy.RevocationMode = [System.Security.Cryptography.X509Certificates.X509RevocationMode]::Online
    if (-not $chain.Build($certificate)) { throw 'The publisher certificate chain is not trusted or revocation could not be checked.' }
} finally { $chain.Dispose() }
$tool = Get-Command $SignToolPath -ErrorAction SilentlyContinue
if (-not $tool -and $SignToolPath -eq 'signtool.exe') {
    $kits = Join-Path ${env:ProgramFiles(x86)} 'Windows Kits\10\bin'
    $candidate = Get-ChildItem -LiteralPath $kits -Directory | Sort-Object Name -Descending | ForEach-Object { Join-Path $_.FullName 'x64\signtool.exe' } | Where-Object { Test-Path -LiteralPath $_ } | Select-Object -First 1
    if ($candidate) { $tool = Get-Command $candidate }
}
if (-not $tool) { throw 'The Windows SDK x64 SignTool was not found.' }
if (-not $Files.Count -or $Files.Count -gt 32) { throw 'Provide 1 to 32 explicit release files.' }
foreach ($inputPath in $Files) {
    $file = Get-Item -LiteralPath $inputPath -ErrorAction Stop
    if ($file.PSIsContainer -or ($file.Attributes -band [IO.FileAttributes]::ReparsePoint) -or $file.Extension -notin @('.exe', '.dll', '.msi', '.ps1')) { throw 'Only regular EXE, DLL, MSI and PowerShell release files can be signed.' }
    & $tool.Source sign /s My /sha1 $CertificateThumbprint /fd SHA256 /tr $TimestampUrl.AbsoluteUri /td SHA256 $file.FullName
    if ($LASTEXITCODE -ne 0) { throw "Authenticode signing failed: $($file.Name)" }
    & $tool.Source verify /pa /all /tw $file.FullName
    if ($LASTEXITCODE -ne 0) { throw "Authenticode signature or timestamp verification failed: $($file.Name)" }
    $signature = Get-AuthenticodeSignature -LiteralPath $file.FullName
    if ($signature.Status -ne 'Valid' -or $signature.SignerCertificate.Thumbprint -ne $CertificateThumbprint -or -not $signature.TimeStamperCertificate) { throw "The expected timestamped publisher signature is missing: $($file.Name)" }
    Write-Output "Verified timestamped publisher signature: $($file.Name)"
}
