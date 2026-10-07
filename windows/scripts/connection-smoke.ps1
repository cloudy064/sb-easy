param(
    [ValidateSet('Debug', 'Release')][string]$Configuration = 'Release',
    [switch]$Tun,
    [switch]$Dashboard
)
$ErrorActionPreference = 'Stop'
$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
$buildDir = Join-Path $repoRoot "build\windows-$($Configuration.ToLowerInvariant())"
$serviceExe = Join-Path $buildDir 'sb-easy-service.exe'
if (-not (Test-Path -LiteralPath (Join-Path $buildDir 'core\sing-box.exe'))) { throw 'Run prepare-core.ps1 first.' }
$elevated = [Security.Principal.WindowsPrincipal]::new([Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if ($Tun -and -not $elevated) { throw 'The isolated TUN acceptance test requires an elevated PowerShell.' }
$testDir = Join-Path $repoRoot ('build\windows-connection-smoke-' + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $testDir | Out-Null
$pipeId = 'sb-easy-connection-smoke-' + [guid]::NewGuid().ToString('N')
$pipeName = '\\.\pipe\' + $pipeId
$dataDir = Join-Path $testDir 'state'
$service = $null; $fixture = $null; $connected = $false; $streamProbe = $null; $desktop = $null
$adapterName = 'sb-easy-test-' + [guid]::NewGuid().ToString('N').Substring(0, 12)
function Read-PipeBytes($Stream, [byte[]]$Buffer) {
    $offset = 0
    while ($offset -lt $Buffer.Length) {
        $pending = $Stream.ReadAsync($Buffer, $offset, $Buffer.Length - $offset)
        if (-not $pending.Wait(40000)) { throw 'Pipe read deadline exceeded.' }
        $count = $pending.Result
        if ($count -le 0) { throw 'Incomplete pipe response.' }
        $offset += $count
    }
}
function Invoke-TestRpc([string]$Method, $Params = @{}, [string]$ExpectedError = '') {
    $stream = [IO.Pipes.NamedPipeClientStream]::new('.', $pipeId, [IO.Pipes.PipeDirection]::InOut, [IO.Pipes.PipeOptions]::Asynchronous)
    try {
        $stream.Connect(5000)
        $body = [Text.Encoding]::UTF8.GetBytes((@{version=1;id=[guid]::NewGuid().ToString('N');method=$Method;params=$Params} | ConvertTo-Json -Depth 10 -Compress))
        $prefix = [BitConverter]::GetBytes([uint32]$body.Length)
        $stream.Write($prefix, 0, 4); $stream.Write($body, 0, $body.Length)
        [byte[]]$header = [byte[]]::new(4)
        Read-PipeBytes $stream $header
        $length = [BitConverter]::ToUInt32($header, 0)
        if (-not $length -or $length -gt 1048576) { throw 'Invalid response length.' }
        [byte[]]$response = [byte[]]::new($length)
        Read-PipeBytes $stream $response
        $decoded = [Text.Encoding]::UTF8.GetString($response) | ConvertFrom-Json
        if ($ExpectedError) {
            if ($decoded.ok -or $decoded.error.code -ne $ExpectedError) { throw "Expected $ExpectedError from $Method." }
            return $decoded
        }
        if (-not $decoded.ok) { throw "$Method failed: $($decoded.error.code): $($decoded.error.message)" }
        return $decoded.result
    } finally { $stream.Dispose() }
}
try {
    $node = (Get-Command node.exe -ErrorAction Stop).Source
    $fixture = Start-Process -FilePath $node -ArgumentList @(('"' + (Join-Path $PSScriptRoot 'fixture-server.mjs') + '"'), ('"' + $testDir + '"')) -PassThru -WindowStyle Hidden -RedirectStandardOutput (Join-Path $testDir 'fixture.log') -RedirectStandardError (Join-Path $testDir 'fixture-error.log')
    $originFile = Join-Path $testDir 'fixture-origin.txt'
    $deadline = [DateTime]::UtcNow.AddSeconds(5)
    while (-not (Test-Path -LiteralPath $originFile)) {
        if ($fixture.HasExited -or [DateTime]::UtcNow -gt $deadline) { throw 'The loopback fixture did not start.' }
        Start-Sleep -Milliseconds 30
    }
    $origin = (Get-Content -LiteralPath $originFile -Raw).Trim()
    $proxyPort = [int](Get-Content -LiteralPath (Join-Path $testDir 'fixture-proxy-port.txt') -Raw)
    $service = Start-Process -FilePath $serviceExe -ArgumentList @('--console','--pipe-name',$pipeName,'--data-dir',('"' + $dataDir + '"')) -PassThru -WindowStyle Hidden -RedirectStandardOutput (Join-Path $testDir 'service.log') -RedirectStandardError (Join-Path $testDir 'service-error.log')
    $uri = 'sbeasy://enroll?server=' + [Uri]::EscapeDataString($origin) + '&code=' + ('a' * 64)
    $null = Invoke-TestRpc 'enrollment.apply' @{uri=$uri}
    $null = Invoke-TestRpc 'config.refresh'
    $status = Invoke-TestRpc 'connection.start'
    $connected = $true
    if ($status.phase -ne 'RUNNING' -or -not $status.core_running -or -not $status.config.active_etag -or $status.tun_active) { throw 'Invalid local core activation status.' }
    # Force SOCKS, including for loopback targets; the response must traverse
    # the actual sing-box mixed inbound instead of curl's NO_PROXY bypass.
    $probe = & curl.exe --silent --show-error --max-time 5 --noproxy never-bypass.invalid --proxy "socks5h://127.0.0.1:$proxyPort" "$origin/connection-probe"
    if ($LASTEXITCODE -ne 0 -or ($probe | ConvertFrom-Json).fixture -ne 'sb-easy-connection-probe') { throw 'Real core proxy forwarding failed.' }
    Write-Output 'PASS: real sing-box started, authenticated local health became ready, and SOCKS forwarded an HTTP request.'
    $inspection = Invoke-TestRpc 'config.inspect'
    if (-not $inspection.active -or $inspection.active.etag -ne $status.config.active_etag -or -not $inspection.candidate) { throw 'Config catalog did not bind to candidate and active revisions.' }
    $telemetry = Invoke-TestRpc 'runtime.snapshot'
    if (-not $telemetry.running -or $telemetry.download_total -le 0 -or $telemetry.upload_total -le 0 -or -not $telemetry.nodes.Count -or $telemetry.etag -ne $status.config.active_etag) { throw 'Real core telemetry did not reflect forwarded traffic.' }
    $serialized = $telemetry | ConvertTo-Json -Depth 15 -Compress
    if ($serialized -match 'Bearer |external_controller|fixture-private-token|fixture-private-password') { throw 'Runtime snapshot leaked private data.' }
    Write-Output 'PASS: config catalog revisions and real core upload/download counters returned through the C service.'
    if ($Dashboard) {
        $streamProbe = Start-Process -FilePath (Get-Command curl.exe).Source -ArgumentList @('--silent','--show-error','--max-time','90','--noproxy','never-bypass.invalid','--proxy',"socks5h://127.0.0.1:$proxyPort",'--output','NUL',"$origin/connection-stream") -PassThru -WindowStyle Hidden -RedirectStandardError (Join-Path $testDir 'stream-error.log')
        $deadline = [DateTime]::UtcNow.AddSeconds(5)
        do {
            $telemetry = Invoke-TestRpc 'runtime.snapshot'
            if ($telemetry.connection_count -gt 0 -and $telemetry.connections[0].download -gt 0) { break }
            Start-Sleep -Milliseconds 100
        } while ([DateTime]::UtcNow -lt $deadline)
        if ($telemetry.connection_count -le 0 -or $telemetry.connections[0].download -le 0) { throw 'The real core did not report the streamed fixture connection.' }
        $desktopExe = Join-Path $buildDir 'sb-easy.exe'
        $views = @(
            @{page='overview';theme='light';width='1120';name='overview-light'},
            @{page='overview';theme='dark';width='1120';name='overview-dark'},
            @{page='proxies';theme='light';width='1120';name='proxies'},
            @{page='connections';theme='dark';width='1120';name='connections'},
            @{page='profiles';theme='light';width='1120';name='profiles'},
            @{page='rules';theme='light';width='1120';name='rules'},
            @{page='activity';theme='light';width='1120';name='activity'},
            @{page='settings';theme='dark';width='760';name='settings-narrow'},
            @{page='connections';theme='light';width='760';name='connections-narrow'}
        )
        foreach ($view in $views) {
            $screenshot = Join-Path $testDir ($view.name + '.png')
            [string[]]$arguments = @('--pipe-name',$pipeName,'--smoke-test',('"'+$screenshot+'"'),'--expect-enrolled','--expect-running','--smoke-page',$view.page,'--smoke-theme',$view.theme,'--smoke-width',$view.width)
            $desktop = Start-Process -FilePath $desktopExe -ArgumentList $arguments -PassThru -WindowStyle Hidden
            if (-not $desktop.WaitForExit(35000) -or $desktop.ExitCode -ne 0 -or -not (Test-Path -LiteralPath $screenshot)) { throw "Dashboard view $($view.name) failed. See $testDir" }
            Write-Output "PASS: real core telemetry, native navigation, theme and no overflow: $screenshot"
        }
        if (-not $streamProbe.HasExited) { Stop-Process -Id $streamProbe.Id -Force; $streamProbe.WaitForExit() }
    }
    $stopped = Invoke-TestRpc 'connection.stop'
    $connected = $false
    if ($stopped.phase -ne 'STOPPED' -or $stopped.core_running -or $stopped.config.active_etag) { throw 'Stop left a stale active revision.' }
    if ($stopped.stop_forced -ne $false) { throw 'The real core required forced termination instead of graceful exit.' }
    $telemetry = Invoke-TestRpc 'runtime.snapshot'
    if ($telemetry.running -or $telemetry.etag -or $telemetry.connections.Count -or $telemetry.nodes.Count) { throw 'Stopped telemetry retained stale runtime data.' }
    $listener = [Net.Sockets.TcpClient]::new()
    try {
        try { $listener.Connect('127.0.0.1', $proxyPort) } catch [Net.Sockets.SocketException] { }
        if ($listener.Connected) { throw 'The stopped core proxy listener is still present.' }
    } finally { $listener.Dispose() }
    Write-Output 'PASS: the real core exited gracefully; disconnect cleared the active revision and closed the proxy listener.'
    $candidate = @{
        inbounds=@(@{type='tun';tag='fixture-tun';interface_name=$adapterName;address=@('198.18.255.1/30');auto_route=$true;route_address=@('198.18.255.0/30');strict_route=$false;stack='system'})
        outbounds=@(@{type='direct';tag='direct'})
        dns=@{servers=@(@{type='local';tag='local'});final='local'}
        route=@{rules=@(@{protocol='dns';action='hijack-dns'});final='direct'}
    }
    $candidate | ConvertTo-Json -Depth 15 | Set-Content -LiteralPath (Join-Path $testDir 'fixture-candidate.json') -Encoding utf8
    $null = Invoke-TestRpc 'config.refresh'
    if ($Tun) {
        # Only a benchmark /30 is routed into this unique temporary adapter.
        # There is no default-route capture or strict-route firewall rule.
        if (Get-NetRoute -DestinationPrefix '198.18.255.0/30' -ErrorAction SilentlyContinue) { throw 'The isolated test prefix is already routed; refusing to change it.' }
        $status = Invoke-TestRpc 'connection.start'
        $connected = $true
        if (-not $status.tun_active -or $status.phase -ne 'RUNNING') { throw 'TUN activation was not reported.' }
        $adapter = Get-NetAdapter -Name $adapterName -ErrorAction Stop
        if (-not (Get-NetRoute -InterfaceIndex $adapter.ifIndex -DestinationPrefix '198.18.255.0/30' -ErrorAction SilentlyContinue)) { throw 'The test TUN route was not created.' }
        $null = Invoke-TestRpc 'connection.stop'
        $connected = $false
        $deadline = [DateTime]::UtcNow.AddSeconds(5)
        do {
            $routes = @(Get-NetRoute -InterfaceIndex $adapter.ifIndex -DestinationPrefix '198.18.255.0/30' -ErrorAction SilentlyContinue)
            if (-not $routes.Count) { break }
            Start-Sleep -Milliseconds 100
        } while ([DateTime]::UtcNow -lt $deadline)
        if ($routes.Count) { throw 'The test TUN route did not disappear after graceful stop.' }
        Write-Output 'PASS: actual Wintun adapter and isolated /30 route created and cleaned after stop.'
    } elseif (-not $elevated) {
        $null = Invoke-TestRpc 'connection.start' @{} 'CORE_ELEVATION_REQUIRED'
        $status = Invoke-TestRpc 'status.get'
        if ($status.core_running -or $status.config.active_etag) { throw 'An unelevated TUN start incorrectly became active.' }
        Write-Output 'PASS: TUN startup refused without elevation; no network adapter or route was changed.'
    }
    Write-Output "Connection acceptance artifacts: $testDir"
} finally {
    if ($desktop -and -not $desktop.HasExited) { Stop-Process -Id $desktop.Id -Force }
    if ($streamProbe -and -not $streamProbe.HasExited) { Stop-Process -Id $streamProbe.Id -Force }
    if ($connected -and $service -and -not $service.HasExited) {
        try { $null = Invoke-TestRpc 'connection.stop' } catch { Write-Warning 'The isolated core required service shutdown after a stop error.' }
    }
    foreach ($process in @($service, $fixture)) {
        if ($process -and -not $process.HasExited) { Stop-Process -Id $process.Id -Force; $process.WaitForExit() }
    }
}
