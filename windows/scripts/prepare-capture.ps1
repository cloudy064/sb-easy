$ErrorActionPreference = 'Stop'
$repo = (Resolve-Path (Join-Path $PSScriptRoot '../..')).Path
$deps = Join-Path $repo 'build/capture-deps'
New-Item -ItemType Directory -Force -Path $deps | Out-Null
function Get-PinnedArchive($Name, $Url, $Hash, $Folder) {
    $file = Join-Path $deps $Name
    if (-not (Test-Path -LiteralPath $file)) { Invoke-WebRequest $Url -OutFile $file }
    if ((Get-FileHash -LiteralPath $file).Hash -ne $Hash) { throw "Invalid capture dependency checksum: $Name" }
    if (-not (Test-Path -LiteralPath (Join-Path $deps $Folder))) {
        $destination = if ($Folder -eq 'flex') { Join-Path $deps 'flex' } else { $deps }
        Expand-Archive -LiteralPath $file -DestinationPath $destination
    }
}
Get-PinnedArchive 'WinDivert-2.2.2-A.zip' 'https://github.com/basil00/WinDivert/releases/download/v2.2.2/WinDivert-2.2.2-A.zip' '63CB41763BB4B20F600B6DE04E991A9C2BE73279E317D4D82F237B150C5F3F15' 'WinDivert-2.2.2-A'
Get-PinnedArchive 'win_flex_bison-2.5.25.zip' 'https://github.com/lexxmark/winflexbison/releases/download/v2.5.25/win_flex_bison-2.5.25.zip' '8D324B62BE33604B2C45AD1DD34AB93D722534448F55A16CA7292DE32B6AC135' 'flex'
$pcap = Join-Path $repo 'android/third_party/libpcap-1.10.6.tar.xz'
if ((Get-FileHash -LiteralPath $pcap).Hash -ne 'EC97D1206BDD19CB6BDD043EAA9F0037AA732262EC68E070FD7C7B5F834D5DFC') { throw 'Invalid libpcap checksum' }
if (-not (Test-Path -LiteralPath (Join-Path $deps 'libpcap-1.10.6'))) {
    & tar -xf $pcap -C $deps
    if ($LASTEXITCODE -ne 0) { throw 'libpcap extraction failed' }
}
# Only stages the driver. WinDivertOpen is called on explicit capture activation.
$licenseRoot=Join-Path $repo 'build/windows-release/licenses'
New-Item -ItemType Directory -Force -Path $licenseRoot | Out-Null
Copy-Item -LiteralPath (Join-Path $deps 'WinDivert-2.2.2-A/LICENSE') -Destination (Join-Path $licenseRoot 'WinDivert.txt')
Copy-Item -LiteralPath (Join-Path $deps 'libpcap-1.10.6/LICENSE') -Destination (Join-Path $licenseRoot 'libpcap.txt')
Write-Output 'Pinned WinDivert and offline libpcap sources prepared; no driver started.'
