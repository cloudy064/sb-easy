param([string]$InstallRoot = "$env:ProgramFiles\sb-easy", [switch]$Portable)
$ErrorActionPreference = 'Stop'
if (-not $Portable -and -not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    $process = Start-Process powershell.exe -Verb RunAs -WindowStyle Hidden -ArgumentList ('-NoProfile -ExecutionPolicy Bypass -File "' + $PSCommandPath + '" -InstallRoot "' + $InstallRoot + '"') -PassThru -Wait
    if ($process.ExitCode -ne 0) { throw 'Extension installation failed.' }
    exit
}
$InstallRoot = (Resolve-Path -LiteralPath $InstallRoot).Path
if (-not (Test-Path -LiteralPath (Join-Path $InstallRoot 'sb-easy-service.exe'))) { throw 'Install the sb-easy base client first.' }
$baseInfo=(Get-Item -LiteralPath (Join-Path $InstallRoot 'sb-easy-service.exe')).VersionInfo
$baseVersion=[version]::new($baseInfo.FileMajorPart,$baseInfo.FileMinorPart,$baseInfo.FileBuildPart,$baseInfo.FilePrivatePart)
if ($baseVersion -lt [version]'0.6.2.0') { throw 'Upgrade the sb-easy base client to 0.6.2 or later first.' }
$hashes = Get-Content -LiteralPath (Join-Path $PSScriptRoot 'checksums.json') -Raw | ConvertFrom-Json
foreach ($item in $hashes) {
    if ($item.path -match '(^[/\\]|\.\.|:)') { throw 'Invalid extension package path.' }
    $file = Join-Path $PSScriptRoot $item.path
    if ((Get-FileHash -LiteralPath $file -Algorithm SHA256).Hash -ne $item.sha256) { throw 'Extension package checksum mismatch.' }
}
$manifest = Get-Content -LiteralPath (Join-Path $PSScriptRoot 'payload\extension.json') -Raw | ConvertFrom-Json
if ($manifest.id -ne 'capture' -or $manifest.api_version -ne 1 -or $manifest.version -ne '1.0.0') { throw 'Incompatible capture extension.' }
$destination = Join-Path $InstallRoot 'extensions\capture'
$ui = Join-Path $InstallRoot 'ui\extensions\capture'
if ((Test-Path -LiteralPath $destination) -or (Test-Path -LiteralPath $ui)) { throw 'Uninstall the existing capture extension from Settings > Extensions before installing this package.' }
# Stage under the target's protected directory, then publish the manifest last.
# No service restart and no changes to capture data or proxy configuration.
New-Item -ItemType Directory -Path $destination,$ui -Force | Out-Null
try {
    foreach ($name in @('sb-easy-capture.exe','capture','licenses')) { Copy-Item -LiteralPath (Join-Path $PSScriptRoot "payload\$name") -Destination $destination -Recurse }
    Copy-Item -Path (Join-Path $PSScriptRoot 'ui\*') -Destination $ui -Recurse
    Copy-Item -LiteralPath (Join-Path $PSScriptRoot 'payload\extension.json') -Destination $destination
} catch {
    # Leave incomplete files disabled for inspection; never touch saved captures.
    throw
}
Write-Output 'Capture extension installed, initially disabled. Open Settings > Extensions to enable it.'
