param([ValidateSet('Debug', 'Release')][string]$Configuration = 'Release')
$ErrorActionPreference = 'Stop'
$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
$buildDir = Join-Path $repoRoot "build\windows-$($Configuration.ToLowerInvariant())"
$serviceExe = Join-Path $buildDir 'sb-easy-service.exe'
$desktopExe = Join-Path $buildDir 'sb-easy.exe'
foreach ($binary in @($serviceExe, $desktopExe)) {
    if (-not (Test-Path -LiteralPath $binary)) { throw "Build the Windows preview first: $binary is missing." }
}
$testDir = Join-Path $repoRoot ('build\windows-smoke-' + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $testDir | Out-Null
$pipeName = '\\.\pipe\sb-easy-smoke-' + [guid]::NewGuid().ToString('N')
$screenshot = Join-Path $testDir 'desktop.png'
$service = $null
$desktop = $null
try {
    $dataDir = Join-Path $testDir 'state'
    $service = Start-Process -FilePath $serviceExe -ArgumentList @('--console', '--pipe-name', $pipeName, '--data-dir', ('"' + $dataDir + '"')) -PassThru -WindowStyle Hidden -RedirectStandardOutput (Join-Path $testDir 'service.log') -RedirectStandardError (Join-Path $testDir 'service-error.log')
    $desktop = Start-Process -FilePath $desktopExe -ArgumentList @('--pipe-name', $pipeName, '--smoke-test', ('"' + $screenshot + '"')) -PassThru -WindowStyle Hidden
    if (-not $desktop.WaitForExit(35000)) { throw 'Desktop smoke test exceeded its deadline.' }
    if ($desktop.ExitCode -ne 0) { throw "Desktop smoke test failed with exit code $($desktop.ExitCode). See $testDir" }
    if (-not (Test-Path -LiteralPath $screenshot)) { throw 'Desktop screenshot was not produced.' }
    Write-Output "PASS: packaged Vue -> WebView2 -> named pipe -> real service; screenshot: $screenshot"
    $narrowScreenshot = Join-Path $testDir 'desktop-narrow.png'
    $desktop = Start-Process -FilePath $desktopExe -ArgumentList @('--pipe-name', $pipeName, '--smoke-test', ('"' + $narrowScreenshot + '"'), '--smoke-width', '760') -PassThru -WindowStyle Hidden
    if (-not $desktop.WaitForExit(35000)) { throw 'Narrow desktop smoke test exceeded its deadline.' }
    if ($desktop.ExitCode -ne 0 -or -not (Test-Path -LiteralPath $narrowScreenshot)) { throw 'Narrow desktop layout failed.' }
    Write-Output "PASS: 760px window has no horizontal overflow; screenshot: $narrowScreenshot"
    Stop-Process -Id $service.Id -Force
    $service.WaitForExit()
    $offlineScreenshot = Join-Path $testDir 'desktop-offline.png'
    $desktop = Start-Process -FilePath $desktopExe -ArgumentList @('--pipe-name', $pipeName, '--smoke-test', ('"' + $offlineScreenshot + '"'), '--expect-disconnected') -PassThru -WindowStyle Hidden
    if (-not $desktop.WaitForExit(35000)) { throw 'Offline desktop smoke test exceeded its deadline.' }
    if ($desktop.ExitCode -ne 0 -or -not (Test-Path -LiteralPath $offlineScreenshot)) { throw 'Desktop did not correctly report an unavailable service.' }
    Write-Output "PASS: absent service is visibly disconnected; screenshot: $offlineScreenshot"
} finally {
    # Only processes created by this test are stopped; no installed service or TUN is touched.
    if ($desktop -and -not $desktop.HasExited) { Stop-Process -Id $desktop.Id -Force }
    if ($service -and -not $service.HasExited) { Stop-Process -Id $service.Id -Force }
}
