param([string]$PythonVersion = '3.13')
$ErrorActionPreference = 'Stop'
$root = (Resolve-Path (Join-Path $PSScriptRoot '../..')).Path
Push-Location $root
try {
    $python = Join-Path $root 'build/httpdebug-venv/Scripts/python.exe'
    if (-not (Test-Path -LiteralPath $python)) {
        & uv venv --python $PythonVersion build/httpdebug-venv
        if ($LASTEXITCODE) { throw 'Python environment setup failed' }
    }
    & uv pip sync --python $python --index-url https://pypi.org/simple extensions/http-debug/requirements-windows.lock
    if ($LASTEXITCODE) { throw 'Pinned dependencies failed to install' }
    & $python extensions/http-debug/tests/test_engine.py
    if ($LASTEXITCODE) { throw 'HTTPS engine acceptance failed' }
    & $python -m PyInstaller --noconfirm --onefile --name sb-easy-http-debug --distpath build/windows-release/extensions/http-debug --workpath build/httpdebug-pyinstaller --specpath build --paths extensions/http-debug --collect-all mitmproxy --collect-all mitmproxy_rs --copy-metadata mitmproxy --collect-all mitmproxy_windows extensions/http-debug/worker.py
    if ($LASTEXITCODE) { throw 'Engine packaging failed' }
    & $python extensions/http-debug/tests/worker_smoke.py build/windows-release/extensions/http-debug/sb-easy-http-debug.exe
    if ($LASTEXITCODE) { throw 'Packaged engine acceptance failed' }
    & $python extensions/http-debug/package.py --licenses-only
    if ($LASTEXITCODE) { throw 'License collection failed' }
    Push-Location windows/ui
    try { & npx.cmd vite build --config vite.plugins.config.ts --mode http-debug; if ($LASTEXITCODE) { throw 'Plugin UI build failed' } }
    finally { Pop-Location }
    Write-Output 'HTTP debug engine and UI built. Build a signed catalog with package-plugins.py --base-url <HTTPS origin> --sequence <next sequence>; embed the reviewed publisher public key in the host.'
} finally { Pop-Location }
