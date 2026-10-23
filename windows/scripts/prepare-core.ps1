param([ValidateSet('Debug', 'Release')][string]$Configuration = 'Release')
$ErrorActionPreference = 'Stop'
$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
$sourceCheckout = Test-Path -LiteralPath (Join-Path $repoRoot 'windows\CMakeLists.txt')
$destinationRoot = if ($sourceCheckout) {
    Join-Path $repoRoot "build\windows-$($Configuration.ToLowerInvariant())"
} else {
    # The portable preview places this script in its scripts/ directory.
    (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
}
$manifestPath = if ($sourceCheckout) { Join-Path $repoRoot 'config\runtime-versions.json' } else { Join-Path $destinationRoot 'runtime-versions.json' }
$manifest = Get-Content -LiteralPath $manifestPath -Raw | ConvertFrom-Json
if ($manifest.schema_version -ne 1) { throw 'Unsupported runtime version manifest.' }
$version = $manifest.sing_box.version
$artifact = $manifest.sing_box.artifacts.'windows-amd64'
$expectedHash = $artifact.sha256
$expectedUrl = "https://github.com/SagerNet/sing-box/releases/download/v$version/sing-box-$version-windows-amd64.zip"
if ($version -notmatch '^\d+\.\d+\.\d+$' -or $expectedHash -notmatch '^[a-fA-F0-9]{64}$' -or $artifact.url -ne $expectedUrl) {
    throw 'Invalid immutable core artifact pin.'
}
# The pinned sing-tun Windows amd64 adapter embeds Wintun. No adjacent
# wintun.dll is consulted or downloaded by this preparation script.
$downloadDir = if ($sourceCheckout) { Join-Path $repoRoot 'build\core-download' } else { Join-Path $destinationRoot 'downloads' }
$archive = Join-Path $downloadDir "sing-box-$version-windows-amd64.zip"
New-Item -ItemType Directory -Path $downloadDir -Force | Out-Null
if (-not (Test-Path -LiteralPath $archive)) {
    Invoke-WebRequest -Uri $artifact.url -OutFile $archive
}
if ((Get-FileHash -LiteralPath $archive -Algorithm SHA256).Hash -ne $expectedHash) {
    throw 'The core archive does not match the pinned official release checksum. It was not installed.'
}
$extractDir = Join-Path $downloadDir ('verified-' + [guid]::NewGuid().ToString('N'))
$coreDir = Join-Path $destinationRoot 'core'
$previousDir = Join-Path $destinationRoot 'core.previous'
$candidateDir = Join-Path $destinationRoot ('core.candidate-' + [guid]::NewGuid().ToString('N'))
try {
    Expand-Archive -LiteralPath $archive -DestinationPath $extractDir
    $sourceDir = Join-Path $extractDir "sing-box-$version-windows-amd64"
    New-Item -ItemType Directory -Path $candidateDir -Force | Out-Null
    foreach ($name in @('sing-box.exe', 'libcronet.dll', 'LICENSE')) {
        Copy-Item -LiteralPath (Join-Path $sourceDir $name) -Destination (Join-Path $candidateDir $name)
    }
    $reported = & (Join-Path $candidateDir 'sing-box.exe') version
    if ($LASTEXITCODE -ne 0 -or $reported[0] -ne "sing-box version $version") {
        throw 'The verified core did not report the pinned version.'
    }
    # Keep a complete previous bundle for rollback. Never replace individual
    # DLL/EXE files across versions or continue after a locked-file failure.
    if (Test-Path -LiteralPath $coreDir) {
        if (Test-Path -LiteralPath $previousDir) { Remove-Item -LiteralPath $previousDir -Recurse -Force }
        Move-Item -LiteralPath $coreDir -Destination $previousDir
    }
    try { Move-Item -LiteralPath $candidateDir -Destination $coreDir }
    catch {
        if (Test-Path -LiteralPath $previousDir) { Move-Item -LiteralPath $previousDir -Destination $coreDir }
        throw
    }
    Write-Output "Pinned sing-box $version prepared at $coreDir. No VPN was started."
    Write-Output 'This core embeds Wintun; no separate wintun.dll download is required.'
} finally {
    if (Test-Path -LiteralPath $extractDir) { Remove-Item -LiteralPath $extractDir -Recurse -Force }
    if (Test-Path -LiteralPath $candidateDir) { Remove-Item -LiteralPath $candidateDir -Recurse -Force }
}
