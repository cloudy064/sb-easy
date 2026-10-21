param([ValidateSet('Debug','Release')][string]$Configuration='Release')
$ErrorActionPreference='Stop'
$repoRoot=(Resolve-Path (Join-Path $PSScriptRoot '../..')).Path
$buildDir=Join-Path $repoRoot "build/windows-$($Configuration.ToLowerInvariant())"
$testDir=Join-Path $repoRoot ('build/ip-check-smoke-'+[guid]::NewGuid().ToString('N'))
$client=Join-Path $testDir 'client'
New-Item -ItemType Directory -Path $client | Out-Null
Copy-Item -LiteralPath (Join-Path $buildDir 'sb-easy-service.exe') -Destination $client
Copy-Item -LiteralPath (Join-Path $buildDir 'core') -Destination $client -Recurse
# Install the locally built, pinned bundle into this disposable client only.
$entry=Get-Content (Join-Path $repoRoot 'build/store-release-index.json') -Raw | ConvertFrom-Json | Where-Object id -eq 'ip-check'
$bundle=Join-Path $repoRoot ('build/'+$entry.file)
if((Get-FileHash -LiteralPath $bundle).Hash.ToLowerInvariant() -ne $entry.sha256){throw 'Bundle hash mismatch'}
$reader=[IO.BinaryReader]::new([IO.File]::OpenRead($bundle))
try {
    if([Text.Encoding]::ASCII.GetString($reader.ReadBytes(8)) -ne 'SBECP001'){throw 'Invalid bundle'}
    foreach($relative in @('extensions/ip-check/extension.json','extensions/ip-check/sb-easy-ip-check.exe','extensions/ip-check/licenses/ip-check.txt','extensions/ip-check/licenses/vue.txt','extensions/ip-check/data/ip-intelligence.sqlite','extensions/ip-check/data/manifest.json','extensions/ip-check/licenses/ip-data.txt','ui/extensions/ip-check/view.js','ui/extensions/ip-check/view.css')){
        $size=$reader.ReadUInt32();$data=$reader.ReadBytes($size)
        if($data.Length -ne $size){throw 'Incomplete bundle'}
        $path=Join-Path $client $relative
        New-Item -ItemType Directory -Force (Split-Path $path) | Out-Null
        [IO.File]::WriteAllBytes($path,$data)
    }
    if($reader.BaseStream.Position -ne $reader.BaseStream.Length){throw 'Unexpected bundle files'}
} finally {$reader.Dispose()}
$pipeId='sb-easy-connection-smoke-'+[guid]::NewGuid().ToString('N')
$pipeName='\\.\pipe\'+$pipeId
$service=$null;$fixture=$null;$connected=$false
function Read-Exact($stream,[byte[]]$data){
    $offset=0
    while($offset -lt $data.Length){
        $pending=$stream.ReadAsync($data,$offset,$data.Length-$offset)
        if(-not $pending.Wait(30000)){throw 'Pipe timeout'}
        $n=$pending.Result;if($n -le 0){throw 'Truncated response'};$offset+=$n
    }
}
function Invoke-Rpc([string]$method,$params=@{}){
    for($attempt=0;$attempt -lt 10;$attempt++){
        $pipe=[IO.Pipes.NamedPipeClientStream]::new('.',$pipeId,[IO.Pipes.PipeDirection]::InOut,[IO.Pipes.PipeOptions]::Asynchronous)
        try {
            $pipe.Connect(5000)
            $data=[Text.Encoding]::UTF8.GetBytes((@{version=1;id=[guid]::NewGuid().ToString('N');method=$method;params=$params}|ConvertTo-Json -Compress -Depth 8))
            $head=[BitConverter]::GetBytes([uint32]$data.Length);$pipe.Write($head,0,4);$pipe.Write($data,0,$data.Length)
            $head=[byte[]]::new(4);Read-Exact $pipe $head;$size=[BitConverter]::ToUInt32($head,0)
            if($size -gt 1048576){throw 'Oversized response'}
            $data=[byte[]]::new($size);Read-Exact $pipe $data
            $reply=[Text.Encoding]::UTF8.GetString($data)|ConvertFrom-Json
            if($reply.ok){return $reply.result}
            if($reply.error.code -ne 'BUSY'){throw ($method+': '+$reply.error.code)}
        } finally {$pipe.Dispose()}
        Start-Sleep -Milliseconds 100
    }
    throw 'Service stayed busy'
}
function Check-Core {
    $snapshot=Invoke-Rpc 'runtime.snapshot'
    if($snapshot.core_pid -ne $script:corePid){throw 'IP check interrupted the isolated main proxy'}
    $selection=$snapshot.nodes | Sort-Object tag | Select-Object tag,selected | ConvertTo-Json -Compress
    if($selection -ne $script:selection){throw 'IP check switched an active proxy group'}
    if((Invoke-Rpc 'config.summary').active_etag -ne $script:activeEtag){throw 'IP check changed active configuration'}
}
try {
    $fixture=Start-Process (Get-Command node.exe).Source -ArgumentList @(('"'+(Join-Path $PSScriptRoot 'fixture-server.mjs')+'"'),('"'+$testDir+'"')) -WindowStyle Hidden -PassThru
    $deadline=[DateTime]::UtcNow.AddSeconds(10)
    $originFile=Join-Path $testDir 'fixture-origin.txt'
    while(-not (Test-Path -LiteralPath $originFile)){if($fixture.HasExited -or [DateTime]::UtcNow -gt $deadline){throw 'Fixture startup failed'};Start-Sleep -Milliseconds 50}
    $origin=(Get-Content $originFile -Raw).Trim()
    $localPort=[int](Get-Content (Join-Path $testDir 'fixture-proxy-port.txt'))
    $candidate=@{inbounds=@(@{type='mixed';tag='fixture-ingress';listen='127.0.0.1';listen_port=$localPort});outbounds=@(@{type='direct';tag='direct'},@{type='http';tag='fixture-probe';server='127.0.0.1';server_port=([uri]$origin).Port;username='fixture-private-user';password='fixture-private-password'},@{type='selector';tag='current-group';outbounds=@('direct','fixture-probe');default='direct'});route=@{final='current-group';rules=@()}}
    $candidate|ConvertTo-Json -Depth 10|Set-Content (Join-Path $testDir 'fixture-candidate.json') -Encoding utf8
    $workerTemp=Join-Path $testDir 'worker-temp'
    New-Item -ItemType Directory -Path $workerTemp | Out-Null
    $previousTemp=$env:TEMP;$previousTmp=$env:TMP
    try {
        $env:TEMP=$workerTemp;$env:TMP=$workerTemp
        $service=Start-Process (Join-Path $client 'sb-easy-service.exe') -ArgumentList @('--console','--pipe-name',$pipeName,'--data-dir',('"'+(Join-Path $testDir 'state')+'"')) -WindowStyle Hidden -PassThru
    } finally {$env:TEMP=$previousTemp;$env:TMP=$previousTmp}
    $null=Invoke-Rpc 'enrollment.apply' @{uri=('sbeasy://enroll?server='+[Uri]::EscapeDataString($origin)+'&code='+('a'*64))}
    $null=Invoke-Rpc 'config.refresh'
    $null=Invoke-Rpc 'connection.start';$connected=$true
    $baseline=Invoke-Rpc 'runtime.snapshot'
    $script:corePid=$baseline.core_pid
    $script:selection=$baseline.nodes | Sort-Object tag | Select-Object tag,selected | ConvertTo-Json -Compress
    $script:activeEtag=(Invoke-Rpc 'config.summary').active_etag
    # A pre-database extension must remain discoverable/removable but cannot run.
    $database=Join-Path $client 'extensions/ip-check/data/ip-intelligence.sqlite'
    $heldDatabase=Join-Path $testDir 'held-ip-intelligence.sqlite'
    Move-Item -LiteralPath $database -Destination $heldDatabase
    try {
        $legacy=(Invoke-Rpc 'extensions.list').extensions | Where-Object id -eq 'ip-check'
        if(-not $legacy.installed -or -not $legacy.needs_update -or $legacy.enabled){throw 'Legacy extension compatibility state is incorrect'}
        $rejected=$false
        try {$null=Invoke-Rpc 'extensions.change' @{id='ip-check';action='enable'}} catch {
            if($_.Exception.Message -notmatch 'EXTENSION_UPDATE_REQUIRED'){throw};$rejected=$true
        }
        if(-not $rejected){throw 'Legacy extension was enabled without its local data'}
    } finally {Move-Item -LiteralPath $heldDatabase -Destination $database}
    $null=Invoke-Rpc 'extensions.change' @{id='ip-check';action='enable'}
    $catalog=Invoke-Rpc 'ipcheck.catalog'
    if(-not @($catalog.nodes|Where-Object tag -eq 'fixture-probe').Count){throw 'Missing candidate node'}
    if(-not $catalog.interfaces.Count){throw 'This smoke test needs an up physical uplink (no requests leave the loopback fixture)'}
    if(($catalog|ConvertTo-Json -Depth 10) -match 'fixture-private'){throw 'Catalog leaked credentials'}
    $iface=$catalog.default_interface;if(-not $iface){$iface=$catalog.interfaces[0].name}
    $null=Invoke-Rpc 'ipcheck.start' @{tags=@('fixture-probe');interface=$iface;ipv6=$false}
    $deadline=[DateTime]::UtcNow.AddSeconds(30)
    do {
        Check-Core
        $state=Invoke-Rpc 'ipcheck.snapshot'
        if([DateTime]::UtcNow -gt $deadline){throw 'Batch timeout'}
        if($state.phase -ne 'running'){break};Start-Sleep -Milliseconds 100
    } while($true)
    if($state.phase -ne 'failed' -or $state.results.Count -ne 1 -or $state.results[0].ipv4.status -ne 'unknown'){throw 'The fixture denial was reported as successful detection'}
    if(($state|ConvertTo-Json -Depth 20) -match 'fixture-private'){throw 'Snapshot leaked credentials'}
    $null=Invoke-Rpc 'ipcheck.start' @{tags=@('fixture-probe');interface=$iface;ipv6=$true}
    $null=Invoke-Rpc 'ipcheck.cancel'
    Check-Core
    $null=Invoke-Rpc 'extensions.change' @{id='ip-check';action='disable'}
    Check-Core
    if(@(Get-ChildItem -LiteralPath $workerTemp -Recurse -File -Filter 'config.json').Count){throw 'Normal worker shutdown left its private configuration'}
    Move-Item -LiteralPath $database -Destination $heldDatabase
    $null=Invoke-Rpc 'extensions.change' @{id='ip-check';action='remove'}
    if(((Invoke-Rpc 'extensions.list').extensions | Where-Object id -eq 'ip-check').installed){throw 'Legacy extension could not be removed'}
    Check-Core
    Write-Output 'PASS: IP check catalog, framed worker, refusal handling, cancellation, legacy upgrade/removal preserve the active isolated proxy and hide credentials.'
    Write-Output "Acceptance artifacts: $testDir"
} finally {
    if($connected -and $service -and -not $service.HasExited){try {$null=Invoke-Rpc 'connection.stop'} catch {}}
    foreach($p in @($service,$fixture)){if($p -and -not $p.HasExited){Stop-Process -Id $p.Id -Force;$p.WaitForExit()}}
}

