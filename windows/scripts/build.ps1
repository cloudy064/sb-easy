param(
    [ValidateSet('Debug', 'Release')][string]$Configuration = 'Release',
    [switch]$SkipUi,
    [switch]$CaptureExtension = $true,
    [switch]$StatisticsExtension = $true,
    [switch]$Clean
)
$ErrorActionPreference = 'Stop'
$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
$vswherePath = Join-Path ${env:ProgramFiles(x86)} 'Microsoft Visual Studio\Installer\vswhere.exe'
if (-not (Test-Path -LiteralPath $vswherePath)) { throw 'Install Visual Studio 2022 or newer Build Tools with C++ tools, Windows SDK and CMake.' }
$vsInstall = (& $vswherePath -latest -version '[17.0,19.0)' -products '*' -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 Microsoft.VisualStudio.Component.VC.CMake.Project -property installationPath)
if (-not $vsInstall) { throw 'Visual Studio 2022 or newer C++/CMake components were not found.' }
$vsInstall = $vsInstall.Trim()
& (Join-Path $vsInstall 'Common7\Tools\Launch-VsDevShell.ps1') -Arch amd64 -HostArch amd64 -SkipAutomaticLocation
# Keep /showIncludes stable so Ninja tracks headers on localized Windows installs.
$env:VSLANG = '1033'
$cmake = Join-Path $vsInstall 'Common7\IDE\CommonExtensions\Microsoft\CMake\CMake\bin\cmake.exe'
$ctest = Join-Path $vsInstall 'Common7\IDE\CommonExtensions\Microsoft\CMake\CMake\bin\ctest.exe'
$ninja = Join-Path $vsInstall 'Common7\IDE\CommonExtensions\Microsoft\CMake\Ninja\ninja.exe'
$buildDir = Join-Path $repoRoot "build\windows-$($Configuration.ToLowerInvariant())"
if (-not $SkipUi) {
    Push-Location (Join-Path $repoRoot 'windows\ui')
    try {
        & npm.cmd ci --no-audit --no-fund
        if ($LASTEXITCODE -ne 0) { throw 'UI dependency restore failed' }
        & npm.cmd test
        if ($LASTEXITCODE -ne 0) { throw 'UI tests failed' }
        & npm.cmd run build
        if ($LASTEXITCODE -ne 0) { throw 'UI build failed' }
        if ($StatisticsExtension) {
            & npm.cmd run build:plugins
            if ($LASTEXITCODE -ne 0) { throw 'Extension UI build failed' }
        }
        if ($CaptureExtension) {
            & npm.cmd run build:capture
            if ($LASTEXITCODE -ne 0) { throw 'Capture extension UI build failed' }
        }
    } finally { Pop-Location }
}
if ($CaptureExtension) { & (Join-Path $PSScriptRoot 'prepare-capture.ps1') }
& $cmake -S (Join-Path $repoRoot 'windows') -B $buildDir -G Ninja "-DCMAKE_MAKE_PROGRAM=$ninja" "-DCMAKE_BUILD_TYPE=$Configuration" "-DSB_EASY_BUILD_CAPTURE_EXTENSION=$($CaptureExtension.IsPresent.ToString().ToUpperInvariant())" "-DSB_EASY_BUILD_STATISTICS_EXTENSION=$($StatisticsExtension.IsPresent.ToString().ToUpperInvariant())"
if ($LASTEXITCODE -ne 0) { throw 'Windows configuration failed' }
$buildArguments = @('--build', $buildDir, '--parallel', '4')
if ($Clean) { $buildArguments += '--clean-first' }
& $cmake @buildArguments
if ($LASTEXITCODE -ne 0) { throw 'Windows build failed' }
& $ctest --test-dir $buildDir --output-on-failure --timeout 30
if ($LASTEXITCODE -ne 0) { throw 'Windows tests failed' }
Write-Output "Windows preview built at $buildDir"
