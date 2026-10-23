param(
    [Parameter(Mandatory)][string]$PreviousMsi,
    [Parameter(Mandatory)][uri]$ManifestUrl,
    [Parameter(Mandatory)][uri]$FailureManifestUrl,
    [Parameter(Mandatory)][ValidatePattern('^[A-Fa-f0-9]{40}$')][string]$PublisherThumbprint
)
# Destructive installer acceptance is deliberately a clean-VM gate. This script
# refuses an existing service, installation or data store; it never trusts a
# test certificate or changes certificate stores. FailureManifestUrl must point
# to a separately signed newer test MSI whose declared core version does not
# match its actual core, so the pre-commit health action must reject it.
$ErrorActionPreference = 'Stop'
if (-not $IsWindows) { throw 'Updater acceptance requires Windows.' }
$principal = [Security.Principal.WindowsPrincipal]::new([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { throw 'Use an elevated PowerShell in a disposable Windows VM.' }
$install = Join-Path $env:ProgramFiles 'sb-easy'
$data = Join-Path $env:ProgramData 'sb-easy'
if ((Get-Service sb-easy -ErrorAction SilentlyContinue) -or (Test-Path -LiteralPath $install) -or (Test-Path -LiteralPath $data)) { throw 'Refusing to modify an existing sb-easy installation or data store.' }
foreach ($url in @($ManifestUrl, $FailureManifestUrl)) { if ($url.Scheme -ne 'https' -or $url.UserInfo -or $url.Query -or $url.Fragment) { throw 'Provide HTTPS manifest direct links without credentials, query or fragment.' } }
$PreviousMsi = (Resolve-Path -LiteralPath $PreviousMsi).Path
$signature = Get-AuthenticodeSignature -LiteralPath $PreviousMsi
if ($signature.Status -ne 'Valid' -or $signature.SignerCertificate.Thumbprint -ne $PublisherThumbprint -or -not $signature.TimeStamperCertificate) { throw 'The initial MSI must have the expected trusted timestamped publisher signature.' }
$testRoot = Join-Path ([IO.Path]::GetTempPath()) ('sbeasy-updater-acceptance-' + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $testRoot | Out-Null
$receipt = [ordered]@{ success = $false; checks = @(); logs = $testRoot; platform = [Environment]::OSVersion.VersionString }
Add-Type @'
using System;
using System.Runtime.InteropServices;
public static class SbUpdatePipeIdentity {
  [DllImport("kernel32.dll", SetLastError=true)] public static extern bool GetNamedPipeServerProcessId(IntPtr handle, out uint processId);
}
'@
function Invoke-Control([string]$Method, [hashtable]$Params = @{}, [int]$Timeout = 15000) {
    $pipe = [IO.Pipes.NamedPipeClientStream]::new('.', 'sb-easy-control-v1', [IO.Pipes.PipeDirection]::InOut, [IO.Pipes.PipeOptions]::Asynchronous)
    try {
        $pipe.Connect(3000)
        [uint32]$serverPid = 0
        $service = Get-CimInstance Win32_Service -Filter "Name='sb-easy'"
        if (-not [SbUpdatePipeIdentity]::GetNamedPipeServerProcessId($pipe.SafePipeHandle.DangerousGetHandle(), [ref]$serverPid) -or $serverPid -ne $service.ProcessId -or $service.StartName -ne 'LocalSystem') { throw 'The control pipe is not owned by the registered LocalSystem service.' }
        $body = [Text.Encoding]::UTF8.GetBytes((@{ version = 1; id = 'updater-acceptance'; method = $Method; params = $Params } | ConvertTo-Json -Depth 8 -Compress))
        $header = [BitConverter]::GetBytes([uint32]$body.Length)
        $pipe.Write($header, 0, 4); $pipe.Write($body, 0, $body.Length); $pipe.Flush()
        function Read-Exact([byte[]]$Buffer) {
            $position = 0
            while ($position -lt $Buffer.Length) {
                $read = $pipe.ReadAsync($Buffer, $position, $Buffer.Length - $position)
                if (-not $read.Wait($Timeout)) { throw 'Native update request timed out.' }
                if ($read.Result -le 0) { throw 'Native update pipe closed.' }
                $position += $read.Result
            }
        }
        Read-Exact $header
        $length = [BitConverter]::ToUInt32($header, 0)
        if ($length -lt 1 -or $length -gt 1048576) { throw 'Invalid native update reply length.' }
        $reply = [byte[]]::new($length); Read-Exact $reply
        return ([Text.Encoding]::UTF8.GetString($reply) | ConvertFrom-Json)
    } finally { $pipe.Dispose() }
}
function Require-Control([string]$Method, [hashtable]$Params = @{}) {
    $reply = Invoke-Control $Method $Params 90000
    if (-not $reply.ok) { throw "Native operation failed: $Method / $($reply.error.code)" }
    return $reply.result
}
function Wait-Update([string[]]$Phases, [int]$Seconds = 180) {
    $deadline = [DateTime]::UtcNow.AddSeconds($Seconds)
    while ([DateTime]::UtcNow -lt $deadline) {
        try {
            $reply = Invoke-Control 'updates.status'
            if ($reply.ok -and $reply.result.phase -in $Phases) { return $reply.result }
            if ($reply.ok -and $reply.result.phase -in @('failed', 'recovery_required')) { throw "UPDATE_TERMINAL:$($reply.result.phase)/$($reply.result.error.code)/$($reply.result.last_result.error_code)" }
        } catch { if ($_.Exception.Message.StartsWith('UPDATE_TERMINAL:')) { throw } }
        Start-Sleep -Milliseconds 500
    }
    throw 'Updater deadline exceeded. Preserve installer state and logs; do not terminate msiexec during a transaction.'
}
function Download-Release([uri]$Url) {
    Require-Control 'updates.check' @{ manifest_url = $Url.AbsoluteUri } | Out-Null
    $available = Wait-Update @('available')
    Require-Control 'updates.download' @{ release_id = $available.release.id } | Out-Null
    return (Wait-Update @('ready') 720)
}
try {
    $installLog = Join-Path $testRoot 'initial-install.log'
    $process = Start-Process msiexec.exe -ArgumentList @('/i', ('"' + $PreviousMsi + '"'), '/qn', '/norestart', '/l*v', ('"' + $installLog + '"')) -PassThru -WindowStyle Hidden
    if (-not $process.WaitForExit(180000) -or $process.ExitCode -notin @(0, 3010)) { throw 'Initial signed MSI installation failed.' }
    $initial = Require-Control 'updates.status'
    if (-not $initial.supported -or -not $initial.publisher_configured) { throw 'The initial MSI was not built with the expected updater publisher.' }
    $oldVersion = $initial.current_version
    Require-Control 'management.settings.set' @{ auto_connect = $false; auto_reconnect = $false; telemetry_enabled = $false; sync_interval_seconds = 240 } | Out-Null
    $stateFile = Join-Path $data 'device-state.dat'
    if (-not (Test-Path -LiteralPath $stateFile -PathType Leaf)) { throw 'The baseline did not persist a real encrypted settings file.' }
    $stateHash = (Get-FileHash -LiteralPath $stateFile -Algorithm SHA256).Hash
    $receipt.checks += 'signed initial MSI and installed-service updater'

    $bad = Download-Release $FailureManifestUrl
    Require-Control 'updates.install' @{ release_id = $bad.release.id } | Out-Null
    $rolledBack = Wait-Update @('rolled_back') 600
    if ($rolledBack.current_version -ne $oldVersion -or -not $rolledBack.last_result.state_restored) { throw 'Health failure did not restore the original MSI version and saved state.' }
    if ((Get-FileHash -LiteralPath $stateFile -Algorithm SHA256).Hash -ne $stateHash) { throw 'Health rollback did not restore the exact original encrypted state bytes.' }
    $settings = Require-Control 'management.settings.get'
    if ($settings.auto_connect -or $settings.auto_reconnect -or $settings.telemetry_enabled -or $settings.sync_interval_seconds -ne 240) { throw 'The restored service did not load the original saved settings.' }
    $receipt.checks += 'new-core health failure caused MSI transaction rollback and configuration restoration'

    $good = Download-Release $ManifestUrl
    $package = Join-Path $data 'updates\staging\package.msi'
    $stream = [IO.File]::Open($package, [IO.FileMode]::Open, [IO.FileAccess]::ReadWrite, [IO.FileShare]::Read)
    try { $first = $stream.ReadByte(); $stream.Position = 0; $stream.WriteByte([byte]($first -bxor 1)); $stream.Flush($true) } finally { $stream.Dispose() }
    $rejected = Invoke-Control 'updates.install' @{ release_id = $good.release.id } 90000
    if ($rejected.ok -or $rejected.error.code -ne 'UPDATE_HASH_MISMATCH') { throw 'Changed staged MSI was not rejected immediately before install.' }
    if ((Require-Control 'updates.status').current_version -ne $oldVersion) { throw 'Rejected package changed the installed application.' }
    $receipt.checks += 'post-download tampering rejected before installation'

    $good = Download-Release $ManifestUrl
    Require-Control 'updates.install' @{ release_id = $good.release.id } | Out-Null
    $complete = Wait-Update @('succeeded') 600
    if ($complete.current_version -ne $good.release.version -or $complete.current_core_version -ne $good.release.core_version) { throw 'Committed application/core pair does not match the signed manifest.' }
    $receipt.checks += 'verified app/core pair installed and healthy before commit'
    $receipt.success = $true
    Write-Output 'Native updater acceptance passed. The disposable VM retains its installation and protected transaction evidence for inspection.'
} finally {
    $receipt | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath (Join-Path $testRoot 'receipt.json') -Encoding utf8
    if (Test-Path -LiteralPath (Join-Path $data 'updates\staging\installer.log')) { Copy-Item -LiteralPath (Join-Path $data 'updates\staging\installer.log') -Destination (Join-Path $testRoot 'latest-installer.log') }
    Write-Output "Receipt: $(Join-Path $testRoot 'receipt.json')"
}
