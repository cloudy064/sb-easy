param([ValidateSet('Debug', 'Release')][string]$Configuration = 'Release')
$ErrorActionPreference = 'Stop'
$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
$buildDir = Join-Path $repoRoot "build\windows-$($Configuration.ToLowerInvariant())"
$serviceExe = Join-Path $buildDir 'sb-easy-service.exe'
$trayExe = Join-Path $buildDir 'sb-easy.exe'
foreach ($binary in @($serviceExe, $trayExe)) {
    if (-not (Test-Path -LiteralPath $binary)) { throw "Build the Windows service and tray first: $binary is missing." }
}
$testDir = Join-Path $repoRoot ('build\windows-smoke-' + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $testDir | Out-Null
$pipeName = '\\.\pipe\sb-easy-smoke-' + [guid]::NewGuid().ToString('N')
$service = $null
$tray = $null
try {
    $dataDir = Join-Path $testDir 'state'
    $service = Start-Process -FilePath $serviceExe -ArgumentList @('--console', '--pipe-name', $pipeName, '--data-dir', ('"' + $dataDir + '"')) -PassThru -WindowStyle Hidden -RedirectStandardOutput (Join-Path $testDir 'service.log') -RedirectStandardError (Join-Path $testDir 'service-error.log')
    $onlineReceipt = Join-Path $testDir 'online.json'
    $tray = Start-Process -FilePath $trayExe -ArgumentList @('--pipe-name', $pipeName, '--smoke-test', ('"' + $onlineReceipt + '"')) -PassThru -WindowStyle Hidden
    if (-not $tray.WaitForExit(35000)) { throw 'Local web smoke test exceeded its deadline.' }
    if ($tray.ExitCode -ne 0 -or -not (Test-Path -LiteralPath $onlineReceipt)) { throw "Local web smoke test failed. See $testDir" }
    $online = Get-Content -LiteralPath $onlineReceipt -Raw | ConvertFrom-Json
    if (-not $online.ok -or -not $online.static_ok -or -not $online.rpc_ok -or -not $online.service_available) { throw 'Local web did not reach the real isolated service.' }
    Write-Output 'PASS: packaged web assets + authenticated HTTP -> verified named pipe -> real service'
    Stop-Process -Id $service.Id -Force
    $service.WaitForExit()
    $offlineReceipt = Join-Path $testDir 'offline.json'
    $tray = Start-Process -FilePath $trayExe -ArgumentList @('--pipe-name', $pipeName, '--smoke-test', ('"' + $offlineReceipt + '"'), '--expect-disconnected') -PassThru -WindowStyle Hidden
    if (-not $tray.WaitForExit(35000)) { throw 'Offline local web smoke test exceeded its deadline.' }
    if ($tray.ExitCode -ne 0 -or -not (Test-Path -LiteralPath $offlineReceipt)) { throw 'Local web did not correctly report an unavailable service.' }
    $offline = Get-Content -LiteralPath $offlineReceipt -Raw | ConvertFrom-Json
    if (-not $offline.ok -or -not $offline.static_ok -or $offline.service_available) { throw 'Invalid disconnected-service receipt.' }
    Write-Output "PASS: absent service is reported as disconnected; receipts: $testDir"
} finally {
    # Stop only processes created here. The installed service and its VPN are never used.
    if ($tray -and -not $tray.HasExited) { Stop-Process -Id $tray.Id -Force }
    if ($service -and -not $service.HasExited) { Stop-Process -Id $service.Id -Force }
}
