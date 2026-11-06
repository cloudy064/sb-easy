[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string] $LauncherPath
)

$ErrorActionPreference = 'Stop'
$launcher = (Resolve-Path -LiteralPath $LauncherPath).Path
$repositoryRoot = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$testRoot = Join-Path $repositoryRoot ('build\setup-launcher-tests\' + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $testRoot -Force | Out-Null
$probePath = Join-Path $testRoot 'probe child.ps1'
$resultPath = Join-Path $testRoot 'child result.json'
$originalTemp = Join-Path $testRoot 'original temporary directory'
New-Item -ItemType Directory -Path $originalTemp | Out-Null
$sentinel = 'inherited value with spaces / 中文'
$argumentValue = 'argument with spaces and 中文'
$quotedValue = 'embedded "quote" and trailing slash\'

@'
param([string] $OutputPath, [string] $Value, [string] $QuotedValue)
$ErrorActionPreference = 'Stop'
[ordered]@{
    temp = $env:TEMP
    tmp = $env:TMP
    sentinel = $env:SB_EASY_SETUP_TEST_SENTINEL
    value = $Value
    quoted_value = $QuotedValue
    temporary_directory_exists = (Test-Path -LiteralPath $env:TEMP -PathType Container)
} | ConvertTo-Json | Set-Content -LiteralPath $OutputPath -Encoding utf8NoBOM
exit 37
'@ | Set-Content -LiteralPath $probePath -Encoding utf8NoBOM

function Invoke-TestLauncher {
    param([string[]] $Arguments, [int] $ExpectedExitCode)

    $start = [System.Diagnostics.ProcessStartInfo]::new($launcher)
    $start.UseShellExecute = $false
    $start.CreateNoWindow = $true
    $start.RedirectStandardOutput = $true
    $start.RedirectStandardError = $true
    foreach ($argument in $Arguments) {
        $start.ArgumentList.Add($argument)
    }
    $start.Environment['TEMP'] = $originalTemp
    $start.Environment['TMP'] = $originalTemp
    $start.Environment['SB_EASY_SETUP_TEST_SENTINEL'] = $sentinel
    $process = [System.Diagnostics.Process]::Start($start)
    $stdout = $process.StandardOutput.ReadToEndAsync()
    $stderr = $process.StandardError.ReadToEndAsync()
    $timer = [System.Diagnostics.Stopwatch]::StartNew()
    try {
        while (-not $process.WaitForExit(25)) {
            $process.Refresh()
            # The old environment-block bug grew memory without starting Burn.
            # Fail before it can exhaust this machine, even ahead of the timeout.
            if ($process.PrivateMemorySize64 -gt 128MB) {
                throw 'Setup launcher exceeded 128 MiB before exiting (possible environment-block loop).'
            }
            if ($timer.Elapsed.TotalSeconds -gt 8) {
                throw 'Setup launcher did not exit within 8 seconds.'
            }
        }
        if ($process.ExitCode -ne $ExpectedExitCode) {
            throw "Expected launcher exit $ExpectedExitCode, received $($process.ExitCode). $($stderr.Result) $($stdout.Result)"
        }
    } finally {
        if (-not $process.HasExited) {
            $process.Kill($true)
            [void] $process.WaitForExit(5000)
        }
        $process.Dispose()
    }
}

Invoke-TestLauncher -ExpectedExitCode 37 -Arguments @(
    '--bundle', (Join-Path $PSHOME 'pwsh.exe'),
    '-NoProfile', '-File', $probePath,
    '-OutputPath', $resultPath, '-Value', $argumentValue, '-QuotedValue', $quotedValue
)
$result = Get-Content -Raw -LiteralPath $resultPath | ConvertFrom-Json
if ($result.sentinel -cne $sentinel -or $result.value -cne $argumentValue -or
    $result.quoted_value -cne $quotedValue) {
    throw 'Launcher did not preserve the inherited environment or command-line arguments.'
}
$workPrefix = Join-Path ([Environment]::GetFolderPath('LocalApplicationData')) 'sb-easy\setup-work\'
if ($result.temp -cne $result.tmp -or $result.temp -eq $originalTemp -or
    -not $result.temp.StartsWith($workPrefix, [StringComparison]::OrdinalIgnoreCase) -or
    -not $result.temporary_directory_exists) {
    throw 'Launcher did not replace both TEMP and TMP with its existing private working directory.'
}
Invoke-TestLauncher -ExpectedExitCode 2 -Arguments @(
    '/quiet', '--bundle', (Join-Path $testRoot 'missing-bootstrapper.exe')
)
Invoke-TestLauncher -ExpectedExitCode 1 -Arguments @('/quiet', '--bundle')
Write-Host "Setup launcher environment, argument forwarding, exit status, and error-path tests passed. Evidence: $testRoot"
