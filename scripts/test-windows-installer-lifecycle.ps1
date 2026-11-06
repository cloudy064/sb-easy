[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string] $SetupPath,

    [string] $PreviousSetupPath,

    [Parameter(Mandatory = $true)]
    [switch] $DisposableVm,

    [switch] $AllowUnsigned
)

$ErrorActionPreference = 'Stop'

if (-not $DisposableVm) {
    throw 'This test installs services and network components. Run it only with -DisposableVm on a disposable Windows VM.'
}
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = [Security.Principal.WindowsPrincipal]::new($identity)
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'The lifecycle test must run from an elevated PowerShell session.'
}

$setup = [System.IO.Path]::GetFullPath($SetupPath)
if (-not (Test-Path -LiteralPath $setup -PathType Leaf)) {
    throw "Setup executable is missing: $setup"
}
if (-not $AllowUnsigned) {
    $signature = Get-AuthenticodeSignature -LiteralPath $setup
    if ($signature.Status -ne [System.Management.Automation.SignatureStatus]::Valid) {
        throw "Setup is not validly Authenticode-signed: $($signature.Status)."
    }
}

$logRoot = Join-Path $env:TEMP ('sb-easy-installer-lifecycle-' + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $logRoot | Out-Null

function Invoke-Setup {
    param(
        [string] $Executable,
        [string] $Action,
        [string] $LogName,
        [string[]] $Variables = @()
    )

    $arguments = @($Action, '/quiet', '/norestart', '/log', (Join-Path $logRoot $LogName))
    $arguments += $Variables
    $process = Start-Process -FilePath $Executable -ArgumentList $arguments -Wait -PassThru
    if ($process.ExitCode -notin @(0, 3010)) {
        throw "$Executable $Action failed with exit code $($process.ExitCode). See $logRoot."
    }
}

function Get-RouteSnapshot {
    @(Get-NetRoute -AddressFamily IPv4, IPv6 -PolicyStore ActiveStore |
        Where-Object { $_.DestinationPrefix -in @('0.0.0.0/0', '::/0') } |
        ForEach-Object {
            "$($_.AddressFamily)|$($_.DestinationPrefix)|$($_.NextHop)|$($_.InterfaceIndex)|$($_.RouteMetric)"
        } | Sort-Object)
}

function Get-DnsSnapshot {
    @(Get-DnsClientServerAddress -AddressFamily IPv4, IPv6 |
        ForEach-Object {
            "$($_.AddressFamily)|$($_.InterfaceIndex)|$(($_.ServerAddresses | Sort-Object) -join ',')"
        } | Sort-Object)
}

function Get-AdapterSnapshot {
    @((Get-NetAdapter -IncludeHidden | ForEach-Object { $_.InterfaceGuid.Guid }) | Sort-Object)
}

function Assert-EqualSnapshot {
    param([object[]] $Before, [object[]] $After, [string] $Description)
    $difference = Compare-Object -ReferenceObject $Before -DifferenceObject $After
    if ($null -ne $difference) {
        throw "$Description was not restored after uninstall:`n$($difference | Out-String)"
    }
}

function Assert-Installed {
    $service = Get-Service -Name 'sb-easy' -ErrorAction Stop
    if ($service.Status -ne 'Running') {
        throw "sb-easy service is not running after setup: $($service.Status)."
    }
    foreach ($path in @(
        "$env:ProgramFiles\sb-easy\sb-easy.exe",
        "$env:ProgramFiles\sb-easy\sb-easy-service.exe"
    )) {
        if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
            throw "Installed payload is missing: $path"
        }
    }
    foreach ($path in @(
        "$env:ProgramData\sb-easy\runtime\sing-box-1.13.12.exe",
        "$env:ProgramData\sb-easy\runtime\wintun.dll"
    )) {
        if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
            throw "Service did not materialize its protected embedded runtime: $path"
        }
    }
    $protocol = (Get-Item -LiteralPath 'Registry::HKEY_LOCAL_MACHINE\Software\Classes\sbeasy\shell\open\command').GetValue('')
    if ($protocol -notmatch 'sb-easy\.exe') {
        throw 'sbeasy protocol registration does not target sb-easy.exe.'
    }
}

function Assert-ServiceCrashRecovery {
    $before = Get-CimInstance -ClassName Win32_Service -Filter "Name='sb-easy'"
    if ($null -eq $before -or $before.State -ne 'Running' -or
        [uint32]$before.ProcessId -eq 0U) {
        throw 'sb-easy service has no running process for the crash-recovery test.'
    }
    $previousProcessId = [uint32]$before.ProcessId
    Stop-Process -Id $previousProcessId -Force

    $deadline = [DateTime]::UtcNow.AddSeconds(45)
    do {
        Start-Sleep -Seconds 1
        $after = Get-CimInstance -ClassName Win32_Service -Filter "Name='sb-easy'"
        if ($null -ne $after -and $after.State -eq 'Running' -and
            [uint32]$after.ProcessId -ne 0U -and
            [uint32]$after.ProcessId -ne $previousProcessId) {
            Write-Host "SCM recovered sb-easy as process $($after.ProcessId)."
            return
        }
    } while ([DateTime]::UtcNow -lt $deadline)

    throw 'SCM did not recover sb-easy within 45 seconds after a forced crash.'
}

function Assert-Uninstalled {
    param([bool] $ExpectDataRemoved)

    Start-Sleep -Seconds 2
    if ($null -ne (Get-Service -Name 'sb-easy' -ErrorAction SilentlyContinue)) {
        throw 'sb-easy service remains registered after uninstall.'
    }
    foreach ($name in @('sb-easy', 'sb-easy-service', 'sing-box')) {
        if ($null -ne (Get-Process -Name $name -ErrorAction SilentlyContinue)) {
            throw "$name remains running after uninstall."
        }
    }
    if (Test-Path -LiteralPath 'Registry::HKEY_LOCAL_MACHINE\Software\Classes\sbeasy') {
        throw 'sbeasy protocol registration remains after uninstall.'
    }
    $dataPath = Join-Path $env:ProgramData 'sb-easy'
    if ($ExpectDataRemoved -and (Test-Path -LiteralPath $dataPath)) {
        throw '%ProgramData%\sb-easy remains after opting into data cleanup.'
    }
    if (-not $ExpectDataRemoved -and -not (Test-Path -LiteralPath $dataPath)) {
        throw '%ProgramData%\sb-easy was removed even though data preservation was selected.'
    }
}

$baselineRoutes = Get-RouteSnapshot
$baselineDns = Get-DnsSnapshot
$baselineAdapters = Get-AdapterSnapshot

try {
    if (-not [string]::IsNullOrWhiteSpace($PreviousSetupPath)) {
        $previousSetup = [System.IO.Path]::GetFullPath($PreviousSetupPath)
        Invoke-Setup -Executable $previousSetup -Action '/install' -LogName 'install-previous.log'
        Assert-Installed
        Invoke-Setup -Executable $setup -Action '/install' -LogName 'upgrade-current.log'
    } else {
        Invoke-Setup -Executable $setup -Action '/install' -LogName 'install-current.log'
    }
    Assert-Installed
    Assert-ServiceCrashRecovery
    Assert-Installed
    Invoke-Setup -Executable $setup -Action '/repair' -LogName 'repair-current.log'
    Assert-Installed
    Invoke-Setup -Executable $setup -Action '/uninstall' -LogName 'uninstall-preserve.log'
    Assert-Uninstalled -ExpectDataRemoved $false
    Assert-EqualSnapshot -Before $baselineRoutes -After (Get-RouteSnapshot) -Description 'Default routes'
    Assert-EqualSnapshot -Before $baselineDns -After (Get-DnsSnapshot) -Description 'DNS server configuration'
    Assert-EqualSnapshot -Before $baselineAdapters -After (Get-AdapterSnapshot) -Description 'Network adapters'

    Invoke-Setup -Executable $setup -Action '/install' -LogName 'install-cleanup-cycle.log'
    Assert-Installed
    Invoke-Setup -Executable $setup -Action '/uninstall' -LogName 'uninstall-cleanup.log' -Variables @('-RemoveUserData=1')
    Assert-Uninstalled -ExpectDataRemoved $true
    Assert-EqualSnapshot -Before $baselineRoutes -After (Get-RouteSnapshot) -Description 'Default routes'
    Assert-EqualSnapshot -Before $baselineDns -After (Get-DnsSnapshot) -Description 'DNS server configuration'
    Assert-EqualSnapshot -Before $baselineAdapters -After (Get-AdapterSnapshot) -Description 'Network adapters'
} finally {
    Write-Host "Lifecycle logs: $logRoot"
}

Write-Host 'Install, service-crash recovery, repair, upgrade (when supplied), preserve-uninstall, cleanup-uninstall, process, route, DNS, and adapter checks passed.'
