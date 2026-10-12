param(
    [ValidateSet('Debug', 'Release')][string]$Configuration = 'Release'
)
$ErrorActionPreference = 'Stop'
$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
$buildDir = Join-Path $repoRoot "build\windows-$($Configuration.ToLowerInvariant())"
$serviceExe = Join-Path $buildDir 'sb-easy-service.exe'
if (-not (Test-Path -LiteralPath (Join-Path $buildDir 'core\sing-box.exe'))) { throw 'Run prepare-core.ps1 first.' }
$testDir = Join-Path ([IO.Path]::GetTempPath()) ('sbext-' + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $testDir | Out-Null
$pipeId = 'sb-easy-connection-smoke-' + [guid]::NewGuid().ToString('N')
$pipeName = '\\.\pipe\' + $pipeId
$dataDir = Join-Path $testDir 'state'
$installRoot=Join-Path $testDir 'client'
New-Item -ItemType Directory -Path $installRoot | Out-Null
Copy-Item -LiteralPath $serviceExe -Destination $installRoot
Copy-Item -LiteralPath (Join-Path $buildDir 'core') -Destination $installRoot -Recurse
$serviceExe=Join-Path $installRoot 'sb-easy-service.exe'
function Install-FromStore([string]$ExtensionId='capture') {
    $null=Invoke-TestRpc 'extensions.install' @{id=$ExtensionId}
    $deadline=[DateTime]::UtcNow.AddSeconds(90)
    do {
        $job=Invoke-TestRpc 'extensions.progress'
        if($job.id -ne $ExtensionId){throw 'Wrong installation identity'}
        if($job.phase -eq 'failed'){throw ('Store installation failed: '+$job.error)}
        if([DateTime]::UtcNow -gt $deadline){throw 'Store installation timeout'}
        if((Invoke-TestRpc 'runtime.snapshot').core_pid -ne $before.core_pid){throw 'Store installation interrupted core'}
        Start-Sleep -Milliseconds 100
    } while($job.phase -ne 'complete')
}
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
    for($attempt=0;$attempt -lt 20;$attempt++) {
        try { return Invoke-RawTestRpc $Method $Params $ExpectedError }
        catch { if($_.Exception.Message -ne 'TEST_RPC_BUSY' -or $attempt -eq 19){throw};Start-Sleep -Milliseconds 100 }
    }
}
function Invoke-RawTestRpc([string]$Method, $Params = @{}, [string]$ExpectedError = '') {
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
        if(-not $decoded.ok -and $decoded.error.code -eq 'BUSY'){throw 'TEST_RPC_BUSY'}
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
      route=@{final='default-node';default_domain_resolver='gpt-dns';rules=@(@{domain_suffix=@('openai.com','chatgpt.com');outbound='node-a'},@{domain_suffix=@('claude.ai','anthropic.com');outbound='node-b'})}
      dns=@{final='gpt-dns';servers=@(@{type='https';tag='gpt-dns';server='1.1.1.1';detour='node-a'});rules=@(@{domain_suffix=@('openai.com','chatgpt.com');server='gpt-dns'},@{domain_suffix=@('claude.ai','anthropic.com');server='gpt-dns'})}
    }
    $candidate | ConvertTo-Json -Depth 20 | Set-Content (Join-Path $testDir 'fixture-candidate.json') -Encoding utf8
    $service=Start-Process $serviceExe -ArgumentList @('--console','--pipe-name',$pipeName,'--data-dir',('"'+$dataDir+'"')) -PassThru -WindowStyle Hidden
    $uri='sbeasy://enroll?server='+[Uri]::EscapeDataString($origin)+'&code='+('a'*64)
    $null=Invoke-TestRpc 'enrollment.apply' @{uri=$uri}
    $null=Invoke-TestRpc 'config.refresh'
    $null=Invoke-TestRpc 'connection.start';$connected=$true
    $before=Invoke-TestRpc 'runtime.snapshot'
    if((Invoke-TestRpc 'extensions.list').extensions[0].installed){throw 'Base unexpectedly contains capture'}
    $null=Invoke-TestRpc 'capture.snapshot' @{} 'EXTENSION_MISSING'
    Install-FromStore
    $ext=(Invoke-TestRpc 'extensions.list').extensions[0]
    if(-not $ext.installed -or $ext.enabled -or $ext.running){throw 'Installation did not start disabled'}
    $null=Invoke-TestRpc 'extensions.change' @{id='capture';action='enable'}
    $capture=Invoke-TestRpc 'capture.snapshot'
    $capture.config.bpf='tcp port 443'
    $null=Invoke-TestRpc 'capture.configure' @{config=$capture.config}
    if(-not (Invoke-TestRpc 'extensions.list').extensions[0].running){throw 'Worker is not running'}
    $worker=Get-Process sb-easy-capture | Where-Object Path -eq (Join-Path $installRoot 'extensions/capture/sb-easy-capture.exe')
    if(-not $worker){throw 'Independent worker not found'}
    Stop-Process -Id $worker.Id
    $null=Invoke-TestRpc 'capture.snapshot' @{} 'EXTENSION_FAILED'
    if((Invoke-TestRpc 'runtime.snapshot').core_pid -ne $before.core_pid){throw 'Worker crash restarted proxy'}
    $null=Invoke-TestRpc 'extensions.change' @{id='capture';action='enable'}
    if((Invoke-TestRpc 'capture.snapshot').config.bpf -ne 'tcp port 443'){throw 'Capture preferences lost after restart'}
    $null=Invoke-TestRpc 'extensions.change' @{id='capture';action='disable'}
    if((Invoke-TestRpc 'extensions.list').extensions[0].enabled){throw 'Disable did not persist'}
    $null=Invoke-TestRpc 'capture.snapshot' @{} 'EXTENSION_MISSING'
    if(Get-Process sb-easy-capture -ErrorAction SilentlyContinue | Where-Object Path -eq (Join-Path $installRoot 'extensions/capture/sb-easy-capture.exe')){throw 'Disabled worker still running'}
    $null=Invoke-TestRpc 'extensions.change' @{id='capture';action='remove'}
    if((Invoke-TestRpc 'extensions.list').extensions[0].installed){throw 'Extension not removed'}
    if((Invoke-TestRpc 'runtime.snapshot').core_pid -ne $before.core_pid){throw 'Extension changes restarted core'}
    $probe=& curl.exe --silent --show-error --max-time 5 --noproxy never-bypass.invalid --proxy "socks5h://127.0.0.1:$proxyPort" 'http://api.openai.com/test/connection-probe'
    if($LASTEXITCODE -ne 0 -or ($probe | ConvertFrom-Json).fixture -ne 'sb-easy-connection-probe'){throw 'Proxy traffic failed after extension changes'}
    Install-FromStore
    $null=Invoke-TestRpc 'extensions.change' @{id='capture';action='enable'}
    if((Invoke-TestRpc 'capture.snapshot').config.bpf -ne 'tcp port 443'){throw 'Uninstall lost saved capture preferences'}
    $null=Invoke-TestRpc 'extensions.change' @{id='capture';action='disable'}
    # Independent statistics lifecycle, with no retrospective counting while off.
    $null=Invoke-TestRpc 'traffic.snapshot' @{} 'EXTENSION_MISSING'
    $null=Invoke-TestRpc 'logs.snapshot'
    Install-FromStore 'statistics'
    $stats=(Invoke-TestRpc 'extensions.list').extensions | Where-Object id -eq 'statistics'
    if(-not $stats.installed -or $stats.enabled){throw 'Statistics not installed disabled'}
    $null=Invoke-TestRpc 'extensions.change' @{id='statistics';action='enable'}
    $zero=Invoke-TestRpc 'traffic.snapshot'
    $null=Invoke-TestRpc 'runtime.snapshot'
    $probe=& curl.exe --silent --show-error --max-time 5 --noproxy never-bypass.invalid --proxy "socks5h://127.0.0.1:$proxyPort" 'http://api.openai.com/test/connection-probe'
    if($LASTEXITCODE -ne 0){throw 'Statistics traffic probe failed'}
    $null=Invoke-TestRpc 'runtime.snapshot'
    $sample=Invoke-TestRpc 'traffic.snapshot'
    if(($sample.upload+$sample.download) -le ($zero.upload+$zero.download)){throw 'Statistics failed to record real proxy traffic'}
    $null=Invoke-TestRpc 'extensions.change' @{id='statistics';action='disable'}
    $null=Invoke-TestRpc 'traffic.snapshot' @{} 'EXTENSION_MISSING'
    if(Get-Process sb-easy-statistics -ErrorAction SilentlyContinue | Where-Object Path -eq (Join-Path $installRoot 'extensions/statistics/sb-easy-statistics.exe')){throw 'Disabled statistics still running'}
    $null=& curl.exe --silent --show-error --max-time 5 --noproxy never-bypass.invalid --proxy "socks5h://127.0.0.1:$proxyPort" 'http://api.openai.com/test/connection-probe'
    $null=Invoke-TestRpc 'extensions.change' @{id='statistics';action='enable'}
    $restored=Invoke-TestRpc 'traffic.snapshot'
    if($restored.upload -ne $sample.upload -or $restored.download -ne $sample.download){throw 'Historical statistics lost on re-enable'}
    $null=Invoke-TestRpc 'runtime.snapshot'
    $rebased=Invoke-TestRpc 'traffic.snapshot'
    if($rebased.upload -ne $sample.upload -or $rebased.download -ne $sample.download){throw 'Disabled-period traffic was recounted'}
    $worker=Get-Process sb-easy-statistics | Where-Object Path -eq (Join-Path $installRoot 'extensions/statistics/sb-easy-statistics.exe')
    Stop-Process -Id $worker.Id
    $null=Invoke-TestRpc 'traffic.snapshot' @{} 'EXTENSION_FAILED'
    if((Invoke-TestRpc 'runtime.snapshot').core_pid -ne $before.core_pid){throw 'Statistics crash restarted proxy'}
    $null=Invoke-TestRpc 'extensions.change' @{id='statistics';action='remove'}
    Install-FromStore 'statistics'
    $null=Invoke-TestRpc 'extensions.change' @{id='statistics';action='enable'}
    $restored=Invoke-TestRpc 'traffic.snapshot'
    if($restored.upload -ne $sample.upload -or $restored.download -ne $sample.download){throw 'Uninstall or crash overwrote saved statistics'}
    $logs=Invoke-TestRpc 'logs.snapshot'
    if($null -eq $logs.lines){throw 'Built-in logs unavailable without plugins'}
    if((Invoke-TestRpc 'extensions.catalog').items | Where-Object id -eq 'network-tools'){throw 'Built-in tools still advertised as a plugin'}
    $null=Invoke-TestRpc 'extensions.install' @{id='network-tools'} 'BUILTIN_FEATURE'
    if(-not ((Invoke-TestRpc 'extensions.list').extensions | Where-Object id -eq 'statistics').running){throw 'Reading built-in tools disturbed statistics'}
    $null=Invoke-TestRpc 'extensions.change' @{id='statistics';action='disable'}
    if((Invoke-TestRpc 'runtime.snapshot').core_pid -ne $before.core_pid){throw 'Plugin lifecycle restarted proxy'}
    Write-Output 'PASS: capture and statistics store downloads; capture and statistics worker crash isolation; statistics collection, disable, persistence, reinstall and no recount of disabled traffic; built-in logs without network-tools installation; unchanged proxy PID.'
} finally {
    if($connected -and $service -and -not $service.HasExited){try{$null=Invoke-TestRpc 'connection.stop'}catch{}}
    foreach($process in @($service,$fixture)){if($process -and -not $process.HasExited){Stop-Process -Id $process.Id}}
}
