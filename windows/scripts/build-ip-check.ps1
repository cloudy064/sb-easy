param(
    [string]$PythonVersion = '3.13.12',
    [string]$SingBox = '',
    [string]$LoopbackInterface = 'Loopback Pseudo-Interface 1'
)
$ErrorActionPreference = 'Stop'
$root = (Resolve-Path (Join-Path $PSScriptRoot '../..')).Path
Push-Location $root
try {
    # Reuse an existing tool runtime without changing its MITM dependencies.
    # A clean checkout gets a small build-only environment instead.
    $python = Join-Path $root 'build/httpdebug-venv/Scripts/python.exe'
    if (-not (Test-Path -LiteralPath $python)) {
        $python = Join-Path $root 'build/ipcheck-venv/Scripts/python.exe'
        if (-not (Test-Path -LiteralPath $python)) {
            & uv venv --python $PythonVersion build/ipcheck-venv
            if ($LASTEXITCODE) { throw 'Python environment setup failed' }
        }
        & uv pip sync --python $python --index-url https://pypi.org/simple extensions/ip-check/requirements-build.lock
        if ($LASTEXITCODE) { throw 'Pinned build dependency installation failed' }
    }
    & $python -m unittest discover -s extensions/ip-check/tests -q
    if ($LASTEXITCODE) { throw 'IP checker unit tests failed' }
    # Do not pick up third-party DLLs or UPX from unrelated tools in PATH.
    $previousPath = $env:PATH
    try {
        $env:PATH = "$env:SystemRoot\System32;$env:SystemRoot"
        & $python -m PyInstaller --noconfirm --clean --noupx --onefile --name sb-easy-ip-check --distpath build/windows-release/extensions/ip-check --workpath build/ipcheck-pyinstaller --specpath build --paths extensions/ip-check extensions/ip-check/worker.py
        if ($LASTEXITCODE) { throw 'IP checker packaging failed' }
    } finally { $env:PATH = $previousPath }
    $dataManifest = Join-Path $root 'build/windows-release/extensions/ip-check/data/manifest.json'
    if (Test-Path -LiteralPath $dataManifest) {
        # This proves the frozen sqlite3 module/DLL can read the real packaged
        # data. It makes no network requests and launches no proxy process.
        $lookup = & 'build/windows-release/extensions/ip-check/sb-easy-ip-check.exe' --lookup-ip '1.1.1.1' | ConvertFrom-Json
        if ($LASTEXITCODE -or $lookup.provider -ne 'sb-easy-offline' -or $lookup.status -ne 'ok') {
            throw 'Packaged offline database lookup failed'
        }
        Write-Output 'Packaged offline database verified with no network access.'
    } else {
        Write-Warning 'Offline data is missing; build the dataset before packaging the installable plugin.'
    }
    if (-not $SingBox) {
        $packaged = Join-Path $root 'build/windows-release/core/sing-box.exe'
        if (Test-Path -LiteralPath $packaged) { $SingBox = $packaged }
    }
    if ($SingBox) {
        & $python extensions/ip-check/tests/worker_smoke.py build/windows-release/extensions/ip-check/sb-easy-ip-check.exe $SingBox --interface $LoopbackInterface
        if ($LASTEXITCODE) { throw 'Packaged IP checker loopback acceptance failed' }
    } else {
        Write-Warning 'Frozen worker smoke test needs -SingBox <verified executable>. No live nodes are tested by this script.'
    }
    # Include Python and freezer redistribution notices with the optional bundle.
    & $python extensions/ip-check/package.py
    if ($LASTEXITCODE) { throw 'IP checker license collection failed' }
    Write-Output 'IP checker worker built; no optional Python engine is added to the base installer.'
} finally { Pop-Location }
