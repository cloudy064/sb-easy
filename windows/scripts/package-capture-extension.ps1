param([ValidateSet('Debug','Release')][string]$Configuration='Release')
$ErrorActionPreference='Stop'
$root=(Resolve-Path (Join-Path $PSScriptRoot '../..')).Path
$binary=Join-Path $root "build/windows-$($Configuration.ToLowerInvariant())/extensions/capture"
$stage=Join-Path $root ('build/capture-extension-package-'+[guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $stage | Out-Null
Copy-Item -LiteralPath $binary -Destination (Join-Path $stage 'payload') -Recurse
# Never distribute locally enabled state or unrelated build artifacts.
$marker=Join-Path $stage 'payload/enabled'
if(Test-Path -LiteralPath $marker){Remove-Item -LiteralPath $marker}
Copy-Item -LiteralPath (Join-Path $root 'windows/ui/dist-capture') -Destination (Join-Path $stage 'ui') -Recurse
$licenses=Join-Path $stage 'payload/licenses'
New-Item -ItemType Directory -Path $licenses -Force | Out-Null
Copy-Item -LiteralPath (Join-Path $root 'build/capture-deps/WinDivert-2.2.2-A/LICENSE') -Destination (Join-Path $licenses 'WinDivert.txt')
Copy-Item -LiteralPath (Join-Path $root 'build/capture-deps/libpcap-1.10.6/LICENSE') -Destination (Join-Path $licenses 'libpcap.txt')
Copy-Item -LiteralPath (Join-Path $root 'windows/ui/node_modules/vue/LICENSE') -Destination (Join-Path $licenses 'vue.txt')
Copy-Item -LiteralPath (Join-Path $root 'windows/licenses/sbj-grisu2-MIT.txt') -Destination $licenses
$hashes=@(Get-ChildItem -LiteralPath (Join-Path $stage 'payload'),(Join-Path $stage 'ui') -Recurse -File | ForEach-Object {
    @{path=$_.FullName.Substring($stage.Length+1).Replace('\','/');sha256=(Get-FileHash -LiteralPath $_.FullName).Hash}
})
$hashes | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $stage 'checksums.json') -Encoding utf8
$manifest=Get-Content -LiteralPath (Join-Path $stage 'payload/extension.json') -Raw | ConvertFrom-Json
if ($manifest.version -notmatch '^[0-9]+\.[0-9]+\.[0-9]+$' -or $manifest.build -lt 2) { throw 'Rebuild the capture worker with a current versioned manifest.' }
$archive=Join-Path $root "build/sb-easy-capture-$($manifest.version)-windows-x64.zip"
Compress-Archive -Path (Join-Path $stage '*') -DestinationPath $archive -Force
Write-Output $stage
Write-Output $archive
