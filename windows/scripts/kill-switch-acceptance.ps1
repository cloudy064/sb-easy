<#
.SYNOPSIS
Checks an installed Windows service against a separate, controlled dual-stack
TCP/UDP/DNS fixture. Observe mode only sends probes and reads status. Lifecycle
mode changes protection/settings, terminates the owned core, and restarts the
installed service; run it on a disposable Windows test machine.
.DESCRIPTION
On the remote fixture host run kill-switch-fixture.py with owned IPv4/IPv6
addresses and DNS port 53. Save its first JSON line as EndpointManifest here.
The existing sb-easy profile must provide working dual-stack TUN and UDP.

Example: .\kill-switch-acceptance.ps1 -EndpointManifest .\endpoints.json -Mode Lifecycle
After a manual adapter change or sleep/resume, repeat Observe mode with the
appropriate ExpectedState and Scenario, and inspect remote receipt logs or an
external packet capture for the run marker. A negative client result alone does
not prove packet absence. Reboot/BFE startup, sleep/resume, network changes and
third-party firewall compatibility remain separate native acceptance cases.

Recovery after an interrupted test, from an elevated local console:
  Stop-Service sb-easy
  & "$env:ProgramFiles\sb-easy\sb-easy-service.exe" --disable-kill-switch
  Start-Service sb-easy
#>
param(
    [Parameter(Mandatory = $true)][string]$EndpointManifest,
    [ValidateSet('Observe', 'Lifecycle')][string]$Mode = 'Observe',
    [ValidateSet('blocked', 'connected', 'baseline')][string]$ExpectedState = 'blocked',
    [ValidatePattern('^[a-z0-9-]{1,24}$')][string]$Scenario = 'manual-observation',
    [string]$OutputPath = (Join-Path $PWD ('kill-switch-' + [guid]::NewGuid().ToString('N') + '.json')),
    [string]$ServiceExecutable = (Join-Path $env:ProgramFiles 'sb-easy\sb-easy-service.exe')
)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$runTag = [guid]::NewGuid().ToString('N').Substring(0, 16)
$manifest = Get-Content -LiteralPath $EndpointManifest -Raw | ConvertFrom-Json
$endpoints = $manifest.endpoints
foreach ($family in @('ipv4', 'ipv6')) {
    $endpoint = $endpoints.$family
    $address = [Net.IPAddress]::Parse([string]$endpoint.address)
    $expectedFamily = if ($family -eq 'ipv4') { [Net.Sockets.AddressFamily]::InterNetwork } else { [Net.Sockets.AddressFamily]::InterNetworkV6 }
    if ($address.AddressFamily -ne $expectedFamily -or [Net.IPAddress]::IsLoopback($address)) { throw 'Use a separate, reachable fixture for both address families.' }
    foreach ($field in @('tcp_port', 'udp_port')) {
        if ([int]$endpoint.$field -lt 1 -or [int]$endpoint.$field -gt 65535) { throw "Invalid $family $field." }
    }
    if ([int]$endpoint.dns_port -ne 53) { throw 'System resolver acceptance requires fixture DNS TCP/UDP port 53.' }
}
$report = [ordered]@{
    run_marker = $runTag; mode = $Mode; scenario = $Scenario
    started_at = [DateTime]::UtcNow.ToString('o'); completed = $false
    checks = [Collections.Generic.List[object]]::new()
    pending_native_evidence = @('external packet receipt/capture review', 'sleep and resume', 'adapter/network change', 'reboot and BFE startup', 'third-party firewall compatibility')
}
$saved = $null; $mutated = $false; $serviceStopped = $false
$oldStreams = [Collections.Generic.List[object]]::new()

function Read-PipeBytes($Stream, [byte[]]$Buffer) {
    $offset = 0
    while ($offset -lt $Buffer.Length) {
        $task = $Stream.ReadAsync($Buffer, $offset, $Buffer.Length - $offset)
        if (-not $task.Wait(40000)) { throw 'Service response deadline exceeded.' }
        $read = $task.Result
        if ($read -le 0) { throw 'Incomplete service response.' }
        $offset += $read
    }
}
function Invoke-Rpc([string]$Method, $Params = @{}) {
    $pipe = [IO.Pipes.NamedPipeClientStream]::new('.', 'sb-easy-control-v1', [IO.Pipes.PipeDirection]::InOut, [IO.Pipes.PipeOptions]::Asynchronous)
    try {
        $pipe.Connect(5000)
        $bytes = [Text.Encoding]::UTF8.GetBytes((@{ version = 1; id = [guid]::NewGuid().ToString('N'); method = $Method; params = $Params } | ConvertTo-Json -Depth 10 -Compress))
        $prefix = [BitConverter]::GetBytes([uint32]$bytes.Length)
        $pipe.Write($prefix, 0, 4); $pipe.Write($bytes, 0, $bytes.Length)
        [byte[]]$header = [byte[]]::new(4); Read-PipeBytes $pipe $header
        $length = [BitConverter]::ToUInt32($header, 0)
        if (-not $length -or $length -gt 1048576) { throw 'Invalid service response length.' }
        [byte[]]$body = [byte[]]::new($length); Read-PipeBytes $pipe $body
        $response = [Text.Encoding]::UTF8.GetString($body) | ConvertFrom-Json
        if (-not $response.ok) { throw ($Method + ' failed: ' + $response.error.code) }
        return $response.result
    } finally { $pipe.Dispose() }
}
function Open-EchoStream($Endpoint) {
    $address = [Net.IPAddress]::Parse([string]$Endpoint.address)
    $client = [Net.Sockets.TcpClient]::new($address.AddressFamily)
    try {
        $task = $client.ConnectAsync($address, [int]$Endpoint.tcp_port)
        if (-not $task.Wait(2500)) { throw 'Echo connect timeout.' }
        $client.ReceiveTimeout = 2000; $client.SendTimeout = 2000
        return $client
    } catch { $client.Dispose(); throw }
}
function Test-StreamEcho($Client, [string]$Marker) {
    try {
        [byte[]]$bytes = [Text.Encoding]::ASCII.GetBytes($Marker)
        $stream = $Client.GetStream(); $stream.Write($bytes, 0, $bytes.Length)
        [byte[]]$reply = [byte[]]::new($bytes.Length); $offset = 0
        while ($offset -lt $reply.Length) {
            $read = $stream.Read($reply, $offset, $reply.Length - $offset)
            if ($read -le 0) { return $false }; $offset += $read
        }
        return [Text.Encoding]::ASCII.GetString($reply) -ceq $Marker
    } catch { return $false }
}
function Test-TcpEcho($Endpoint, [string]$Marker) {
    $client = $null
    try { $client = Open-EchoStream $Endpoint; return Test-StreamEcho $client $Marker }
    catch { return $false }
    finally { if ($client) { $client.Dispose() } }
}
function Test-UdpEcho($Endpoint, [string]$Marker) {
    $address = [Net.IPAddress]::Parse([string]$Endpoint.address)
    $client = [Net.Sockets.UdpClient]::new($address.AddressFamily)
    try {
        $client.Client.ReceiveTimeout = 2500; $client.Connect($address, [int]$Endpoint.udp_port)
        [byte[]]$bytes = [Text.Encoding]::ASCII.GetBytes($Marker)
        $null = $client.Send($bytes, $bytes.Length)
        $peer = [Net.IPEndPoint]::new($address, 0)
        $reply = $client.Receive([ref]$peer)
        return [Text.Encoding]::ASCII.GetString($reply) -ceq $Marker
    } catch { return $false }
    finally { $client.Dispose() }
}
function Test-SystemDns($Endpoint, [string]$Marker, [bool]$Tcp) {
    $job = Start-Job -ArgumentList @([string]$Endpoint.address, ($Marker + '.sbeasy.test'), $Tcp) -ScriptBlock {
        param($Address, $Name, $TcpOnly)
        $arguments = @{ Server = $Address; Name = $Name; Type = 'A'; DnsOnly = $true; NoHostsFile = $true; QuickTimeout = $true; ErrorAction = 'Stop' }
        if ($TcpOnly) { $arguments.TcpOnly = $true }
        try { @(Resolve-DnsName @arguments | Where-Object IPAddress -eq '198.18.0.1').Count -gt 0 }
        catch { $false }
    }
    try {
        if (-not (Wait-Job $job -Timeout 8)) { return $false }
        return @(Receive-Job $job -ErrorAction SilentlyContinue | Where-Object { $_ -eq $true }).Count -gt 0
    } finally { Stop-Job $job -ErrorAction SilentlyContinue; Remove-Job $job -Force -ErrorAction SilentlyContinue }
}
function Record-Check([string]$Phase, [string]$Kind, [bool]$Actual, [bool]$Expected, [string]$Marker) {
    $report.checks.Add([ordered]@{ time = [DateTime]::UtcNow.ToString('o'); phase = $Phase; kind = $Kind; expected_success = $Expected; actual_success = $Actual; marker = $Marker })
    Write-Output ($Phase + ': ' + $Kind + ' ' + $(if ($Actual -eq $Expected) { 'PASS' } else { 'FAIL' }))
    if ($Actual -ne $Expected) { throw ($Phase + ': unexpected ' + $Kind + ' reachability.') }
}
function Check-Network([string]$Phase, [bool]$Expected) {
    foreach ($family in @('ipv4', 'ipv6')) {
        $endpoint = $endpoints.$family
        foreach ($kind in @('tcp', 'udp', 'dns-udp', 'dns-tcp')) {
            $marker = '{0}-{1}-{2}-{3}' -f $runTag, $Phase, $family, $kind
            $actual = switch ($kind) {
                'tcp' { Test-TcpEcho $endpoint $marker }
                'udp' { Test-UdpEcho $endpoint $marker }
                'dns-udp' { Test-SystemDns $endpoint $marker $false }
                'dns-tcp' { Test-SystemDns $endpoint $marker $true }
            }
            Record-Check $Phase ($family + '-' + $kind) $actual $Expected $marker
        }
    }
}
function Check-Protection([bool]$Tun) {
    $settings = Invoke-Rpc 'management.settings.get'
    if (-not $settings.kill_switch.enabled -or -not $settings.kill_switch.persistent -or
        $settings.kill_switch.tun_allowed -ne $Tun) { throw 'Actual WFP protection/TUN state is inconsistent.' }
}
try {
    if ($Mode -eq 'Observe') {
        $report.initial_status = Invoke-Rpc 'status.get'
        if ($ExpectedState -eq 'blocked' -and -not $report.initial_status.management.kill_switch.enabled) { throw 'Blocked observation requires active WFP protection.' }
        if ($ExpectedState -eq 'connected' -and (-not $report.initial_status.tun_active -or -not $report.initial_status.management.kill_switch.enabled)) { throw 'Connected observation requires an active protected TUN.' }
        if ($ExpectedState -eq 'baseline' -and ($report.initial_status.core_running -or $report.initial_status.management.kill_switch.enabled)) { throw 'Baseline observation requires protection disabled and core disconnected.' }
        Check-Network $Scenario ($ExpectedState -ne 'blocked')
    } else {
        $principal = [Security.Principal.WindowsPrincipal]::new([Security.Principal.WindowsIdentity]::GetCurrent())
        if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { throw 'Lifecycle mode requires an elevated local console.' }
        $serviceInfo = Get-CimInstance Win32_Service -Filter "Name='sb-easy'"
        if ($serviceInfo.StartMode -ne 'Auto' -or $serviceInfo.State -ne 'Running') { throw 'Install and start the automatic sb-easy Windows service first.' }
        $saved = Invoke-Rpc 'management.settings.get'; $status = Invoke-Rpc 'status.get'
        if ($saved.kill_switch_enabled -or $status.core_running) { throw 'Begin with protection disabled and the core disconnected on the test machine.' }
        $null = Invoke-Rpc 'management.settings.set' @{ auto_connect = $false; auto_reconnect = $false }
        $mutated = $true
        Check-Network 'baseline' $true
        foreach ($family in @('ipv4', 'ipv6')) {
            $client = Open-EchoStream $endpoints.$family
            $oldStreams.Add(@{ family = $family; client = $client })
            if (-not (Test-StreamEcho $client ($runTag + '-existing-' + $family))) { throw 'Initial stream echo failed.' }
        }
        $null = Invoke-Rpc 'management.settings.set' @{ kill_switch_enabled = $true }
        Check-Protection $false
        foreach ($existing in $oldStreams) {
            $marker = $runTag + '-revoked-' + $existing.family
            Record-Check 'enabled-disconnected' ($existing.family + '-existing-flow') (Test-StreamEcho $existing.client $marker) $false $marker
            $existing.client.Dispose()
        }
        $oldStreams.Clear()
        Check-Network 'disconnected' $false
        $status = Invoke-Rpc 'connection.start'
        if (-not $status.tun_active) { throw 'This acceptance profile must use a dual-stack TUN.' }
        Check-Protection $true; Check-Network 'connected' $true
        $snapshot = Invoke-Rpc 'runtime.snapshot'
        $core = Get-Process -Id ([int]$snapshot.core_pid)
        if ($core.ProcessName -ne 'sing-box') { throw 'Refusing to terminate an unexpected core process.' }
        Stop-Process -Id $core.Id -Force
        Check-Network 'core-crash' $false
        $null = Invoke-Rpc 'connection.start'; Check-Protection $true; Check-Network 'recovered' $true
        $serviceInfo = Get-CimInstance Win32_Service -Filter "Name='sb-easy'"
        if (-not $serviceInfo.ProcessId) { throw 'The installed service process is not running.' }
        Stop-Process -Id ([int]$serviceInfo.ProcessId) -Force; $serviceStopped = $true
        Check-Network 'service-crash' $false
        Start-Service sb-easy; $serviceStopped = $false
        Start-Sleep -Seconds 2
        Check-Protection $false
        Stop-Service sb-easy -Force; $serviceStopped = $true
        Check-Network 'service-stop' $false
        Start-Service sb-easy; $serviceStopped = $false
        Start-Sleep -Seconds 2
        Check-Protection $false; Check-Network 'service-restart' $false
        $null = Invoke-Rpc 'management.settings.set' @{ kill_switch_enabled = $false }
        Check-Network 'explicit-disable' $true
    }
    $report.completed = $true
} catch {
    $report.failure = $_.Exception.Message
    throw
} finally {
    foreach ($existing in $oldStreams) { $existing.client.Dispose() }
    if ($mutated) {
        try {
            if ($serviceStopped) { Start-Service sb-easy; Start-Sleep -Seconds 2 }
            $null = Invoke-Rpc 'connection.stop'
            $null = Invoke-Rpc 'management.settings.set' @{ kill_switch_enabled = $false; auto_connect = [bool]$saved.auto_connect; auto_reconnect = [bool]$saved.auto_reconnect }
            $report.cleanup = 'restored'
        } catch {
            $report.cleanup = 'service-recovery-required'
            try {
                Stop-Service sb-easy -Force -ErrorAction SilentlyContinue
                & $ServiceExecutable --disable-kill-switch
                if ($LASTEXITCODE -ne 0) { throw 'Local protection recovery failed.' }
                Start-Service sb-easy
                $report.cleanup = 'emergency-protection-disabled'
            } catch { $report.cleanup_error = $_.Exception.Message }
        }
    }
    $report.finished_at = [DateTime]::UtcNow.ToString('o')
    $report | ConvertTo-Json -Depth 20 | Set-Content -LiteralPath $OutputPath -Encoding UTF8
    Write-Output ('Report: ' + $OutputPath + '; remote receipt marker: ' + $runTag)
}
