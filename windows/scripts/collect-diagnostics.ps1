param(
    [string]$OutputDirectory = [Environment]::GetFolderPath('Desktop'),
    [string]$DataDirectory = '',
    [switch]$NoOpen
)
$ErrorActionPreference = 'Stop'
$admin = [Security.Principal.WindowsPrincipal]::new([Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $DataDirectory -and -not $admin) {
    $arguments = @('-NoProfile','-ExecutionPolicy','Bypass','-File',('"'+$PSCommandPath+'"'),'-OutputDirectory',('"'+$OutputDirectory+'"'))
    if ($NoOpen) { $arguments += '-NoOpen' }
    Start-Process powershell.exe -Verb RunAs -WindowStyle Hidden -ArgumentList $arguments
    exit
}
$OutputDirectory = (Resolve-Path -LiteralPath $OutputDirectory).Path
$stage = Join-Path $OutputDirectory ('sb-easy-diagnostics-' + (Get-Date -Format 'yyyyMMdd-HHmmss') + '-' + [guid]::NewGuid().ToString('N').Substring(0,8))
New-Item -ItemType Directory -Path $stage | Out-Null
function Save-Json([string]$Name, $Value) {
    ConvertTo-Json -InputObject $Value -Depth 16 | Set-Content -LiteralPath (Join-Path $stage $Name) -Encoding UTF8
}
function Rpc([string]$Method) {
    $pipe=[IO.Pipes.NamedPipeClientStream]::new('.', 'sb-easy-control-v1', [IO.Pipes.PipeDirection]::InOut, [IO.Pipes.PipeOptions]::Asynchronous)
    try {
        $pipe.Connect(2000)
        $body=[Text.Encoding]::UTF8.GetBytes((@{version=1;id='diagnostic-export';method=$Method;params=@{}}|ConvertTo-Json -Compress))
        $header=[BitConverter]::GetBytes([uint32]$body.Length)
        $pipe.Write($header,0,4);$pipe.Write($body,0,$body.Length)
        function Read-Exact([byte[]]$Buffer) {
            $offset=0
            while($offset -lt $Buffer.Length) {
                $pending=$pipe.ReadAsync($Buffer,$offset,$Buffer.Length-$offset)
                if(-not $pending.Wait(6000)){throw 'Local service read timed out'}
                $n=$pending.Result;if(-not $n){throw 'Local service pipe closed'};$offset+=$n
            }
        }
        Read-Exact $header
        $size=[BitConverter]::ToUInt32($header,0)
        if(-not $size -or $size -gt 1048576){throw 'Invalid local service response'}
        $bytes=[byte[]]::new($size);Read-Exact $bytes
        [Text.Encoding]::UTF8.GetString($bytes)|ConvertFrom-Json
    } finally {$pipe.Dispose()}
}
try {
    [string[]]$roots=if($DataDirectory){@($DataDirectory)}else{@((Join-Path $env:ProgramData 'sb-easy/core-work'),(Join-Path $env:LOCALAPPDATA 'sb-easy/dev-service/core-work'))}
    $copied=@()
    for($r=0;$r -lt $roots.Count;$r++) {
        for($i=0;$i -lt 4;$i++) {
            $path=Join-Path $roots[$r] "diagnostic-$i.log"
            if(-not (Test-Path -LiteralPath $path)){continue}
            $item=Get-Item -LiteralPath $path
            if(($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -or $item.Length -gt 4194304){continue}
            $source=[IO.File]::Open($path,[IO.FileMode]::Open,[IO.FileAccess]::Read,([IO.FileShare]::ReadWrite -bor [IO.FileShare]::Delete))
            try {
                $target=Join-Path $stage "source-$r-diagnostic-$i.log"
                $dest=[IO.File]::Create($target)
                try {
                    # Freeze the byte limit at open, even while the logger writes.
                    $left=[Math]::Min($source.Length,4194304);$buffer=[byte[]]::new(65536)
                    while($left -gt 0){$n=$source.Read($buffer,0,[int][Math]::Min($left,$buffer.Length));if(-not $n){break};$dest.Write($buffer,0,$n);$left-=$n}
                } finally {$dest.Dispose()}
                $copied+=Split-Path $target -Leaf
            } finally {$source.Dispose()}
        }
    }
    Save-Json 'manifest.json' @{version='0.6.1';captured_utc=[DateTime]::UtcNow.ToString('o');logs=$copied;contains='Sanitized core logs, domain/IP/node names, local network state. No device state or raw configuration.'}
    foreach($method in @('status.get','config.inspect','runtime.snapshot','traffic.snapshot','logs.snapshot')) {
        try {Save-Json ($method+'.json') (Rpc $method)} catch {Save-Json ($method+'.json') @{unavailable=$true;reason=$_.Exception.Message}}
    }
    Save-Json 'adapters.json' @(Get-NetAdapter -ErrorAction SilentlyContinue | Select-Object Name,InterfaceIndex,Status,InterfaceDescription)
    Save-Json 'routes.json' @(Get-NetRoute -ErrorAction SilentlyContinue | Select-Object AddressFamily,DestinationPrefix,InterfaceAlias,NextHop,RouteMetric,InterfaceMetric)
    Save-Json 'dns-servers.json' @(Get-DnsClientServerAddress -ErrorAction SilentlyContinue | Select-Object InterfaceAlias,AddressFamily,ServerAddresses)
    Save-Json 'dns-cache.json' @(Get-DnsClientCache -ErrorAction SilentlyContinue | Where-Object Entry -match '(openai|chatgpt|anthropic|claude)\.' | Select-Object Entry,Data,Type,Status,TimeToLive)
    $processes=@(Get-Process -ErrorAction SilentlyContinue | Where-Object ProcessName -match '^(codex|sb-easy|sing-box|clash|verge|msedge|chrome)' | Select-Object Id,ProcessName)
    Save-Json 'processes.json' $processes
    Save-Json 'tcp-connections.json' @(Get-NetTCPConnection -ErrorAction SilentlyContinue | Where-Object OwningProcess -in $processes.Id | Select-Object OwningProcess,State,LocalAddress,LocalPort,RemoteAddress,RemotePort)
    $proxy=Get-ItemProperty 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings'
    Save-Json 'system-proxy.json' @{enabled=$proxy.ProxyEnable;proxy_configured=[bool]$proxy.ProxyServer;pac_configured=[bool]$proxy.AutoConfigURL}
    $archive=$stage+'.zip'
    Compress-Archive -LiteralPath $stage -DestinationPath $archive
    Write-Output $archive
    if(-not $NoOpen){Start-Process explorer.exe -ArgumentList ('/select,"'+$archive+'"')}
} catch {
    $_.Exception.Message | Set-Content -LiteralPath (Join-Path $stage 'export-error.txt') -Encoding UTF8
    if(-not $NoOpen){Start-Process explorer.exe -ArgumentList ('"'+$stage+'"')}
    throw
}
