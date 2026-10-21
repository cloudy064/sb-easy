param(
    [Parameter(Mandatory)][string]$Payload,
    [string]$Version = '0.7.1',
    [string]$WixPath = 'wix'
)
$ErrorActionPreference = 'Stop'
if ($Version -notmatch '^\d{1,3}\.\d{1,3}\.\d{1,5}$') { throw 'MSI Version must be major.minor.build.' }
$parts = $Version.Split('.') | ForEach-Object { [int]$_ }
if ($parts[0] -gt 255 -or $parts[1] -gt 255 -or $parts[2] -gt 65535) { throw 'Version exceeds Windows Installer limits.' }
$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
$Payload = (Resolve-Path -LiteralPath $Payload).Path
foreach ($name in @('sb-easy.exe', 'sb-easy-service.exe', 'WebView2Loader.dll', 'ui\index.html')) {
    if (-not (Test-Path -LiteralPath (Join-Path $Payload $name))) { throw "Missing package payload: $name" }
}
$output = Join-Path $repoRoot "build\sb-easy-$Version-windows-x64.msi"
& $WixPath build (Join-Path $repoRoot 'windows\installer\Package.wxs') -arch x64 `
    -ext WixToolset.UI.wixext/5.0.2 -d "Payload=$Payload" -d "Version=$Version" -o $output -wx
if ($LASTEXITCODE -ne 0) { throw 'MSI build/validation failed. Install pinned WiX 5.0.2 and its UI extension; see windows/README.md.' }
Get-FileHash -LiteralPath $output -Algorithm SHA256
