param(
    [ValidateSet('Debug', 'Release')][string]$Configuration = 'Release',
    [switch]$ValidateCore,
    [switch]$ConnectCore,
    [switch]$AutoStartService
)
$ErrorActionPreference = 'Stop'
$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
$buildDir = Join-Path $repoRoot "build\windows-$($Configuration.ToLowerInvariant())"
$serviceExe = Join-Path $buildDir 'sb-easy-service.exe'
$desktopExe = Join-Path $buildDir 'sb-easy.exe'
if (($ValidateCore -or $ConnectCore) -and -not (Test-Path -LiteralPath (Join-Path $buildDir 'core\sing-box.exe'))) {
    throw 'Run windows/scripts/prepare-core.ps1 before using -ValidateCore.'
}
[string[]]$validationArguments = @()
if ($ValidateCore) { $validationArguments += '--smoke-validate' }
if ($ConnectCore) { $validationArguments += '--smoke-connect' }
$testDir = Join-Path $repoRoot ('build\windows-enrollment-smoke-' + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $testDir | Out-Null
$pipeName = '\\.\pipe\sb-easy-enrollment-smoke-' + [guid]::NewGuid().ToString('N')
$dataDir = Join-Path $testDir 'state'
Set-Content -LiteralPath (Join-Path $testDir 'pipe-name.txt') -Value $pipeName -Encoding utf8
Write-Output "Enrollment smoke artifacts: $testDir"
if ($AutoStartService) { $validationArguments += @('--smoke-start-service', '--smoke-service-data', ('"' + $dataDir + '"')) }
$service = $null; $desktop = $null; $fixture = $null
function Start-TestService {
    if ($AutoStartService) { return $null }
    Start-Process -FilePath $serviceExe -ArgumentList @('--console', '--pipe-name', $pipeName, '--data-dir', ('"' + $dataDir + '"')) -PassThru -WindowStyle Hidden
}
function Find-AutoBackend {
    @(Get-CimInstance Win32_Process -Filter "Name='sb-easy-service.exe'" | Where-Object {
        $_.ExecutablePath -eq $serviceExe -and $_.CommandLine -like ('*' + $pipeName + '*')
    })
}
function Read-AutoBackend {
    $backends = Find-AutoBackend
    if ($backends.Count -ne 1 -or $backends[0].ParentProcessId -ne $desktop.Id) { throw 'GUI did not start exactly one owned backend.' }
    Get-Process -Id $backends[0].ProcessId
}
try {
    $node = (Get-Command node.exe -ErrorAction Stop).Source
    $fixtureScript = Join-Path $PSScriptRoot 'fixture-server.mjs'
    $fixture = Start-Process -FilePath $node -ArgumentList @(('"' + $fixtureScript + '"'), ('"' + $testDir + '"')) -PassThru -WindowStyle Hidden -RedirectStandardOutput (Join-Path $testDir 'fixture.log') -RedirectStandardError (Join-Path $testDir 'fixture-error.log')
    $originFile = Join-Path $testDir 'fixture-origin.txt'
    $deadline = [DateTime]::UtcNow.AddSeconds(5)
    while (-not (Test-Path -LiteralPath $originFile)) {
        if ($fixture.HasExited -or [DateTime]::UtcNow -gt $deadline) { throw 'Loopback fixture failed to start.' }
        Start-Sleep -Milliseconds 50
    }
    $origin = (Get-Content -LiteralPath $originFile -Raw).Trim()
    $service = Start-TestService
    $enrolledImage = Join-Path $testDir 'enrolled.png'
    $desktop = Start-Process -FilePath $desktopExe -ArgumentList (@('--pipe-name', $pipeName, '--smoke-test', ('"' + $enrolledImage + '"'), '--smoke-control-plane', $origin) + $validationArguments) -PassThru -WindowStyle Hidden
    if (-not $desktop.WaitForExit(60000)) { throw 'Enrollment UI smoke exceeded its deadline.' }
    if ($desktop.ExitCode -ne 0) { throw "Enrollment UI smoke failed ($($desktop.ExitCode)). Artifacts: $testDir" }
    if ($AutoStartService) { $service = Read-AutoBackend }
    $receipt = Get-Content -LiteralPath (Join-Path $testDir 'fixture-receipt.json') -Raw | ConvertFrom-Json
    if ($receipt.enrollments -ne 1 -or $receipt.configRequests -ne 1 -or $receipt.rejected -ne 0) { throw 'Enrollment/configuration receipt mismatch.' }
    if (-not (Test-Path -LiteralPath (Join-Path $dataDir 'device-state.dat'))) { throw 'Encrypted state was not persisted.' }
    Write-Output "PASS: actual GUI enrollment and authenticated config download; screenshot: $enrolledImage"
    if ($ValidateCore) { Write-Output 'PASS: GUI called actual sing-box check; candidate validated without activation.' }
    if ($ConnectCore) { Write-Output 'PASS: GUI started a real core, observed its authenticated health/active revision, and disconnected.' }

    # Simulate abrupt process termination. Only the isolated fixture's service is stopped.
    Stop-Process -Id $service.Id -Force
    $service.WaitForExit()
    $service = Start-TestService
    $restoredImage = Join-Path $testDir 'restored.png'
    $desktop = Start-Process -FilePath $desktopExe -ArgumentList (@('--pipe-name', $pipeName, '--smoke-test', ('"' + $restoredImage + '"'), '--expect-enrolled', '--smoke-refresh') + $validationArguments) -PassThru -WindowStyle Hidden
    if (-not $desktop.WaitForExit(60000)) { throw 'Restored UI smoke exceeded its deadline.' }
    if ($desktop.ExitCode -ne 0) { throw "Restored UI smoke failed ($($desktop.ExitCode)). Artifacts: $testDir" }
    if ($AutoStartService) { $service = Read-AutoBackend }
    $receipt = Get-Content -LiteralPath (Join-Path $testDir 'fixture-receipt.json') -Raw | ConvertFrom-Json
    if ($receipt.enrollments -ne 1 -or $receipt.notModified -ne 1 -or $receipt.rejected -ne 0) { throw 'Restart/ETag 304 receipt mismatch.' }
    Write-Output "PASS: DPAPI state recovered after restart and conditional refresh returned 304; screenshot: $restoredImage"
    if ($ValidateCore) { Write-Output 'PASS: restored candidate revalidated by actual sing-box check.' }
    if ($ConnectCore) { Write-Output 'PASS: restored candidate connected and disconnected through the real GUI.' }
    if ($AutoStartService) { Write-Output 'PASS: GUI alone started and recovered the hidden backend; no manual service process was launched.' }
} finally {
    foreach ($process in @($desktop, $service, $fixture)) {
        if ($process -and -not $process.HasExited) { Stop-Process -Id $process.Id -Force }
    }
    if ($AutoStartService) {
        foreach ($backend in (Find-AutoBackend)) { Stop-Process -Id $backend.ProcessId -Force -ErrorAction SilentlyContinue }
    }
}
