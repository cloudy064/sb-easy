param(
    [Parameter(Mandatory)][string]$Payload,
    [string]$Version,
    [string]$WixPath = 'wix'
)
$ErrorActionPreference = 'Stop'
$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
if (-not $Version) {
    $clientVersions = Get-Content -LiteralPath (Join-Path $repoRoot 'config/client-releases.json') -Raw | ConvertFrom-Json
    if ($clientVersions.schema_version -ne 1) { throw 'Unsupported client version manifest.' }
    $Version = [string]$clientVersions.development.windows.version
}
if ($Version -notmatch '^(0|[1-9][0-9]{0,2})\.(0|[1-9][0-9]{0,2})\.(0|[1-9][0-9]{0,4})$') { throw 'MSI Version must be canonical major.minor.build.' }
$parts = $Version.Split('.') | ForEach-Object { [int]$_ }
if ($parts[0] -gt 255 -or $parts[1] -gt 255 -or $parts[2] -gt 65535) { throw 'Version exceeds Windows Installer limits.' }
$Payload = (Resolve-Path -LiteralPath $Payload).Path
foreach ($name in @('sb-easy.exe', 'sb-easy-service.exe', 'sb-easy-update.exe', 'WebView2Loader.dll', 'ui\index.html')) {
    if (-not (Test-Path -LiteralPath (Join-Path $Payload $name))) { throw "Missing package payload: $name" }
}
$output = Join-Path $repoRoot "build\sb-easy-$Version-windows-x64.msi"
& $WixPath build (Join-Path $repoRoot 'windows\installer\Package.wxs') -arch x64 `
    -ext WixToolset.UI.wixext/5.0.2 -d "Payload=$Payload" -d "Version=$Version" -o $output -wx
if ($LASTEXITCODE -ne 0) { throw 'MSI build/validation failed. Install pinned WiX 5.0.2 and its UI extension; see windows/README.md.' }
Get-FileHash -LiteralPath $output -Algorithm SHA256
