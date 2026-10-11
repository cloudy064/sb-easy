param(
    [Parameter(Mandatory)][string]$Msi,
    [Parameter(Mandatory)][string]$PreviousMsi,
    [switch]$WaitForDesktopCheck
)
# Run on a disposable Windows machine, elevated. Never replace an existing
# installation or inspect/remove an existing device store.
$ErrorActionPreference = 'Stop'
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
if (-not ([Security.Principal.WindowsPrincipal]::new($identity)).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'Installer smoke tests require an elevated PowerShell on a clean test machine.'
}
$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
$Msi = (Resolve-Path -LiteralPath $Msi).Path
$PreviousMsi = (Resolve-Path -LiteralPath $PreviousMsi).Path
$installDir = Join-Path $env:ProgramFiles 'sb-easy'
$dataDir = Join-Path $env:ProgramData 'sb-easy'
if ((Get-Service sb-easy -ErrorAction SilentlyContinue) -or (Test-Path -LiteralPath $installDir) -or
    (Test-Path -LiteralPath $dataDir) -or (Get-Process sb-easy,sb-easy-service -ErrorAction SilentlyContinue)) {
    throw 'Refusing to test on a machine with an existing sb-easy installation, data directory or running process.'
}
$testDir = Join-Path $repoRoot ('build\windows-installer-smoke-' + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $testDir | Out-Null
$receipt = [ordered]@{ directory = $testDir; checks = @(); success = $false }
$installedMsi = $null
function Invoke-Msi([string]$Name, [string[]]$Arguments, [int[]]$Expected = @(0)) {
    $log = Join-Path $testDir "$Name.log"
    $process = Start-Process msiexec.exe -ArgumentList ($Arguments + @('/qn', '/norestart', '/l*v', ('"' + $log + '"'))) -WindowStyle Hidden -PassThru
    if (-not $process.WaitForExit(120000)) { throw "Installer timeout: $log (do not terminate Windows Installer during rollback)." }
    if ($process.ExitCode -notin $Expected) { throw "Installer $Name failed: $($process.ExitCode); see $log" }
    $receipt.checks += $Name
}
function Assert-Installed {
    $service = Get-CimInstance Win32_Service -Filter "Name='sb-easy'"
    if (-not $service -or $service.State -ne 'Running' -or $service.StartMode -ne 'Auto' -or
        $service.StartName -ne 'LocalSystem' -or $service.PathName -ne ('"' + (Join-Path $installDir 'sb-easy-service.exe') + '"')) {
        throw 'Installed service identity/startup did not match the MSI contract.'
    }
    foreach ($file in @('sb-easy.exe', 'sb-easy-service.exe', 'WebView2Loader.dll', 'ui\index.html', 'core\sing-box.exe', 'core\LICENSE')) {
        if (-not (Test-Path -LiteralPath (Join-Path $installDir $file))) { throw "Missing installed file: $file" }
    }
    foreach ($folder in @([Environment]::GetFolderPath('CommonDesktopDirectory'), [Environment]::GetFolderPath('CommonPrograms'))) {
        if (-not (Test-Path -LiteralPath (Join-Path $folder 'sb-easy.lnk'))) { throw "Missing shortcut in $folder" }
    }
    $pipe = [IO.Pipes.NamedPipeClientStream]::new('.', 'sb-easy-control-v1', [IO.Pipes.PipeDirection]::InOut, [IO.Pipes.PipeOptions]::Asynchronous)
    try {
        $pipe.Connect(5000)
        $request = [Text.Encoding]::UTF8.GetBytes('{"version":1,"id":"installer","method":"status.get","params":{}}')
        $header = [BitConverter]::GetBytes([uint32]$request.Length)
        $pipe.Write($header, 0, 4); $pipe.Write($request, 0, $request.Length); $pipe.Flush()
        function Read-Exact([byte[]]$Buffer) {
            $offset = 0
            while ($offset -lt $Buffer.Length) {
                $pending = $pipe.ReadAsync($Buffer, $offset, $Buffer.Length - $offset)
                if (-not $pending.Wait(5000)) { throw 'Service diagnostic read timed out.' }
                $read = $pending.Result
                if ($read -eq 0) { throw 'Service closed the diagnostic pipe.' }
                $offset += $read
            }
        }
        Read-Exact $header
        $size = [BitConverter]::ToUInt32($header, 0)
        if ($size -gt 1048576) { throw 'Invalid diagnostic reply size.' }
        $body = [byte[]]::new($size); Read-Exact $body
        $response = [Text.Encoding]::UTF8.GetString($body) | ConvertFrom-Json
        if (-not $response.ok -or $response.result.core_running -or $response.result.enrolled) {
            throw 'A new installation must answer IPC and remain disconnected/unregistered.'
        }
    } finally { $pipe.Dispose() }
}
try {
    Invoke-Msi 'install-previous' @('/i', ('"' + $PreviousMsi + '"'))
    $installedMsi = $PreviousMsi
    Assert-Installed
    $marker = Join-Path $dataDir 'installer-smoke-retention.txt'
    'installer smoke data retention' | Set-Content -LiteralPath $marker
    Invoke-Msi 'upgrade' @('/i', ('"' + $Msi + '"'))
    $installedMsi = $Msi
    Assert-Installed
    if (-not (Test-Path -LiteralPath $marker)) { throw 'Upgrade lost device data.' }
    Remove-Item -LiteralPath (Join-Path $installDir 'ui\index.html')
    Invoke-Msi 'repair' @('/fa', ('"' + $Msi + '"'))
    Assert-Installed
    Invoke-Msi 'reject-downgrade' @('/i', ('"' + $PreviousMsi + '"')) @(1603, 1638)
    Assert-Installed
    if ($WaitForDesktopCheck) {
        # An unelevated caller can now exercise the installed WebView2 host.
        $testDir | Set-Content -LiteralPath (Join-Path $repoRoot 'build\installer-desktop-ready.txt')
        $deadline = [DateTime]::UtcNow.AddSeconds(90)
        while (-not (Test-Path -LiteralPath (Join-Path $testDir 'desktop-passed.txt'))) {
            if ([DateTime]::UtcNow -gt $deadline) { throw 'Unelevated desktop check timed out.' }
            Start-Sleep -Milliseconds 250
        }
        $receipt.checks += 'unelevated-desktop'
    }
    Invoke-Msi 'uninstall' @('/x', ('"' + $Msi + '"'))
    $installedMsi = $null
    if ((Get-Service sb-easy -ErrorAction SilentlyContinue) -or (Test-Path -LiteralPath (Join-Path $installDir 'sb-easy.exe'))) {
        throw 'Uninstall left the service or application executable behind.'
    }
    foreach ($folder in @([Environment]::GetFolderPath('CommonDesktopDirectory'), [Environment]::GetFolderPath('CommonPrograms'))) {
        if (Test-Path -LiteralPath (Join-Path $folder 'sb-easy.lnk')) { throw 'Uninstall left a shortcut behind.' }
    }
    if (-not (Test-Path -LiteralPath $marker)) { throw 'Uninstall deleted retained device data.' }
    $receipt.checks += 'data-retained'
    $receipt.success = $true
} finally {
    if ($installedMsi) { Invoke-Msi 'cleanup' @('/x', ('"' + $installedMsi + '"')) }
    # Only remove the test-owned store after successful service removal. The
    # preflight guarantees it did not exist before this run; no enrollment occurs.
    $expectedData = [IO.Path]::GetFullPath((Join-Path $env:ProgramData 'sb-easy'))
    if (-not (Get-Service sb-easy -ErrorAction SilentlyContinue) -and (Test-Path -LiteralPath $dataDir)) {
        $resolvedData = (Resolve-Path -LiteralPath $dataDir).Path
        if ($resolvedData -ne $expectedData -or (Get-Item -LiteralPath $dataDir).Attributes -band [IO.FileAttributes]::ReparsePoint) {
            throw 'Refusing to clean an unexpected test store path.'
        }
        Remove-Item -LiteralPath $resolvedData -Recurse -Force
    }
    $receipt | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath (Join-Path $testDir 'receipt.json')
}
Write-Output "PASS: MSI lifecycle; receipt: $testDir\receipt.json"
