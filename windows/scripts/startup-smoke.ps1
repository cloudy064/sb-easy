param([ValidateSet('Debug', 'Release')][string]$Configuration = 'Release')
$ErrorActionPreference = 'Stop'
$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
$buildDir = Join-Path $repoRoot "build\windows-$($Configuration.ToLowerInvariant())"
$desktopExe = Join-Path $buildDir 'sb-easy.exe'
$serviceExe = Join-Path $buildDir 'sb-easy-service.exe'
$testDir = Join-Path $repoRoot ('build\windows-startup-smoke-' + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $testDir | Out-Null
$pipeName = '\\.\pipe\sb-easy-startup-smoke-' + [guid]::NewGuid().ToString('N')
$dataDir = Join-Path $testDir 'state'
$desktop = $null
$ownedPids = [System.Collections.Generic.HashSet[int]]::new()

function Find-TestBackend {
    @(Get-CimInstance Win32_Process -Filter "Name='sb-easy-service.exe'" | Where-Object {
        $_.ExecutablePath -eq $serviceExe -and $_.CommandLine -like ('*' + $pipeName + '*')
    })
}

function Open-TestDesktop([string]$Name) {
    $screenshot = Join-Path $testDir ($Name + '.png')
    $script:desktop = Start-Process -FilePath $desktopExe -ArgumentList @(
        '--pipe-name', $pipeName, '--smoke-start-service', '--smoke-service-data', ('"' + $dataDir + '"'),
        '--smoke-test', ('"' + $screenshot + '"')
    ) -PassThru -WindowStyle Hidden
    $parentId = $script:desktop.Id
    if (-not $script:desktop.WaitForExit(35000)) { throw 'Automatic-start desktop exceeded its deadline.' }
    if ($script:desktop.ExitCode -ne 0 -or -not (Test-Path -LiteralPath $screenshot)) {
        throw "Automatic-start desktop failed. See $testDir"
    }
    $backends = Find-TestBackend
    if ($backends.Count -ne 1) { throw "Expected exactly one isolated backend; found $($backends.Count)." }
    $backendId = [int]$backends[0].ProcessId
    $null = $ownedPids.Add($backendId)
    if ((Get-Process -Id $backendId).MainWindowHandle -ne [IntPtr]::Zero) { throw 'Background startup exposed a visible console window.' }
    [pscustomobject]@{ ui_pid = $parentId; backend_pid = $backendId; parent_pid = [int]$backends[0].ParentProcessId; screenshot = $screenshot }
}

try {
    $first = Open-TestDesktop 'first-open'
    if ($first.parent_pid -ne $first.ui_pid) { throw 'The desktop did not launch its own background backend.' }
    $second = Open-TestDesktop 'reopened'
    if ($second.backend_pid -ne $first.backend_pid) { throw 'Reopening created another backend instead of reusing it.' }
    $backend = Get-Process -Id $first.backend_pid
    Stop-Process -Id $backend.Id -Force
    if (-not $backend.WaitForExit(5000)) { throw 'The owned backend did not exit.' }
    $recovered = Open-TestDesktop 'recovered'
    if ($recovered.backend_pid -eq $first.backend_pid -or $recovered.parent_pid -ne $recovered.ui_pid) {
        throw 'The desktop did not recover the stopped background backend.'
    }
    @($first, $second, $recovered) | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $testDir 'startup-receipt.json') -Encoding utf8
    Write-Output "PASS: desktop-only hidden startup, UI exit leaves backend alive, reopening reuses one PID, crash recovery; screenshots: $testDir"
} finally {
    if ($desktop -and -not $desktop.HasExited) { Stop-Process -Id $desktop.Id -Force }
    # Only this script's unique pipe and exact executable path are eligible.
    # Never stop the normal portable backend, an installed service or any TUN.
    foreach ($backend in (Find-TestBackend)) {
        if ($ownedPids.Contains([int]$backend.ProcessId) -or ($desktop -and $backend.ParentProcessId -eq $desktop.Id)) {
            Stop-Process -Id $backend.ProcessId -Force -ErrorAction SilentlyContinue
        }
    }
}
