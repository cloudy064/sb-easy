param(
    [ValidateSet('Debug', 'Release')][string]$Configuration = 'Release'
)
$ErrorActionPreference = 'Stop'
$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
$buildDir = Join-Path $repoRoot "build\windows-$($Configuration.ToLowerInvariant())"
$serviceExe = Join-Path $buildDir 'sb-easy-service.exe'
if (-not (Test-Path -LiteralPath (Join-Path $buildDir 'core\sing-box.exe'))) { throw 'Run prepare-core.ps1 first.' }
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
    $node=(Get-Command node.exe).Source
    $fixture=Start-Process $node -ArgumentList @(('"'+(Join-Path $PSScriptRoot 'fixture-server.mjs')+'"'),('"'+$testDir+'"')) -PassThru -WindowStyle Hidden
    $originFile=Join-Path $testDir 'fixture-origin.txt'
    $deadline=[DateTime]::UtcNow.AddSeconds(5)
    while(-not (Test-Path $originFile)){if([DateTime]::UtcNow -gt $deadline){throw 'Fixture timeout'};Start-Sleep -Milliseconds 30}
    $origin=(Get-Content $originFile -Raw).Trim()
    $proxyPort=[int](Get-Content (Join-Path $testDir 'fixture-proxy-port.txt'))
    $remotePort=([uri]$origin).Port
    $nodes=@('node-a','node-b','default-node') | ForEach-Object { @{type='http';tag=$_;server='127.0.0.1';server_port=$remotePort} }
    $candidate=@{
      inbounds=@(@{type='mixed';tag='local';listen='127.0.0.1';listen_port=$proxyPort})
      outbounds=@($nodes)
      route=@{final='default-node';default_domain_resolver='gpt-dns';rules=@(@{domain_suffix=@('openai.com','chatgpt.com');outbound='node-a'})}
      dns=@{servers=@(@{type='https';tag='gpt-dns';server='1.1.1.1';detour='node-a'});rules=@(@{domain_suffix=@('openai.com','chatgpt.com');server='gpt-dns'})}
    }
    $candidate | ConvertTo-Json -Depth 20 | Set-Content (Join-Path $testDir 'fixture-candidate.json') -Encoding utf8
    $service=Start-Process $serviceExe -ArgumentList @('--console','--pipe-name',$pipeName,'--data-dir',('"'+$dataDir+'"')) -PassThru -WindowStyle Hidden
    $uri='sbeasy://enroll?server='+[Uri]::EscapeDataString($origin)+'&code='+('a'*64)
    $null=Invoke-TestRpc 'enrollment.apply' @{uri=$uri}
    $null=Invoke-TestRpc 'config.refresh'
    $null=Invoke-TestRpc 'connection.start';$connected=$true
    $before=Invoke-TestRpc 'runtime.snapshot'
    $streamProbe=Start-Process curl.exe -ArgumentList @('--silent','--show-error','--max-time','60','--noproxy','never-bypass.invalid','--proxy',"socks5h://127.0.0.1:$proxyPort",'--output','NUL','http://api.openai.com/test/connection-stream') -PassThru -WindowStyle Hidden
    $deadline=[DateTime]::UtcNow.AddSeconds(8)
    do {
      $live=Invoke-TestRpc 'runtime.snapshot'
      if($live.download_total -gt 0){break}
      Start-Sleep -Milliseconds 100
    } while([DateTime]::UtcNow -lt $deadline)
    if($live.download_total -le 0){throw 'Long-lived GPT stream did not start'}
    foreach($choice in @(@('routing.gpt_node',@{outbound='node-b'},'node-b'),@('routing.gpt_default',@{},'default-node'),@('routing.gpt_server',@{},'node-a'))) {
      $null=Invoke-TestRpc $choice[0] $choice[1]
      $after=Invoke-TestRpc 'runtime.snapshot'
      $group=$after.nodes | Where-Object tag -eq 'sb-easy-local-gpt'
      if($after.core_pid -ne $before.core_pid -or $group.selected -ne $choice[2] -or $streamProbe.HasExited){throw 'Live routing restarted the core, broke the old stream, or selected the wrong exit'}
      $probe=& curl.exe --silent --show-error --max-time 5 --noproxy never-bypass.invalid --proxy "socks5h://127.0.0.1:$proxyPort" 'http://api.openai.com/test/connection-probe'
      if($LASTEXITCODE -ne 0 -or ($probe | ConvertFrom-Json).fixture -ne 'sb-easy-connection-probe'){throw 'New GPT connection failed after live selection'}
    }
    $stateFile=Join-Path $dataDir 'device-state.dat'
    $held=[IO.File]::Open($stateFile,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read)
    try { $null=Invoke-TestRpc 'routing.gpt_node' @{outbound='node-b'} 'STORAGE_ERROR' }
    finally { $held.Dispose() }
    $after=Invoke-TestRpc 'runtime.snapshot'
    if(($after.nodes | Where-Object tag -eq 'sb-easy-local-gpt').selected -ne 'node-a'){throw 'Storage failure did not restore the live exit'}
    $null=Invoke-TestRpc 'routing.gpt_node' @{outbound='missing'} 'GPT_OUTBOUND_UNAVAILABLE'
    $after=Invoke-TestRpc 'runtime.snapshot'
    if($after.core_pid -ne $before.core_pid -or ($after.nodes | Where-Object tag -eq 'sb-easy-local-gpt').selected -ne 'node-a'){throw 'Rejected node changed running core'}
    Write-Output 'PASS: node/default/server switches keep the same PID, preserve a GPT stream, and route new GPT requests; missing node is rejected and storage failure rolls back the live exit.'
} finally {
    if($streamProbe -and -not $streamProbe.HasExited){Stop-Process -Id $streamProbe.Id}
    if($connected -and $service -and -not $service.HasExited){try{$null=Invoke-TestRpc 'connection.stop'}catch{}}
    foreach($process in @($service,$fixture)){if($process -and -not $process.HasExited){Stop-Process -Id $process.Id}}
}
