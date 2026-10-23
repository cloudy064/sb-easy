#!/usr/bin/env bash
set -euo pipefail
repo_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)
output_dir=${1:-"$repo_dir/build/linux-core"}
mkdir -p -- "$output_dir"
output_dir=$(cd -- "$output_dir" && pwd)
version=$(python3 "$repo_dir/scripts/runtime-manifest.py" get sing_box.version)
revision=$(python3 "$repo_dir/scripts/runtime-manifest.py" get sing_box.source_revision)
source_url=$(python3 "$repo_dir/scripts/runtime-manifest.py" get sing_box.source_url)
source_dir="$output_dir/source"
if [[ ! -d "$source_dir/.git" ]]; then
    if [[ -n ${SBL_CORE_SOURCE:-} ]]; then
        git clone --no-hardlinks --no-checkout -- "$SBL_CORE_SOURCE" "$source_dir"
        git -C "$source_dir" switch --detach "$revision"
    else
        git clone --depth 1 --branch "v$version" -- "$source_url" "$source_dir"
    fi
    touch "$source_dir/.sb-easy-linux-core-owned"
fi
[[ -f "$source_dir/.sb-easy-linux-core-owned" ]] || { echo 'Use a build directory created by this script' >&2; exit 1; }
[[ $(git -C "$source_dir" rev-parse HEAD) == "$revision" ]] || { echo 'Core source revision does not match the repository pin' >&2; exit 1; }
git -C "$source_dir" diff --quiet HEAD -- || { echo 'Pinned core tracked files have local changes' >&2; exit 1; }
mkdir -p -- "$source_dir/cmd/sb-easy-bridge"
python3 - "$repo_dir/singbox-bridge" "$source_dir/cmd/sb-easy-bridge" <<'PY_COPY'
import pathlib, shutil, sys
source, destination = map(pathlib.Path, sys.argv[1:])
for old in destination.glob('*.go'):
    old.unlink()
for file in source.glob('*.go'):
    if not file.name.endswith('_test.go'):
        shutil.copyfile(file, destination / file.name)
PY_COPY
(
    cd -- "$source_dir"
    python3 "$repo_dir/singbox-bridge/prepare-overlay.py" --output "$output_dir/bridge-overlay.json"
    CGO_ENABLED=1 go build -modfile "$output_dir/bridge-overlay.mod" -buildmode=c-archive -trimpath \
        -tags 'with_gvisor,with_quic,with_wireguard,with_utls,with_clash_api,netgo,osusergo,badlinkname,tfogo_checklinkname0' \
        -ldflags "-s -w -buildid= -checklinkname=0 -X github.com/sagernet/sing-box/constant.Version=$version" \
        -o "$output_dir/libsb_easy_singbox.a" ./cmd/sb-easy-bridge
)
rg -q 'SBEasySingBoxCancelStart' "$output_dir/libsb_easy_singbox.h"
python3 - "$repo_dir" "$output_dir" "$version" "$revision" <<'PY'
import hashlib, json, pathlib, sys
root, output = map(pathlib.Path, sys.argv[1:3])
def digest(path):
    with path.open('rb') as f:
        return hashlib.file_digest(f, 'sha256').hexdigest()
record = {'schema': 1, 'sing_box': sys.argv[3], 'revision': sys.argv[4],
          'bridge_files': {file.name: digest(file) for file in sorted((root / 'singbox-bridge').glob('*.go')) if not file.name.endswith('_test.go')},
          'overlay_script_sha256': digest(root / 'singbox-bridge/prepare-overlay.py'),
          'dependency_overlay': json.loads((output / 'bridge-overlay.json').read_text()),
          'archive_sha256': digest(output / 'libsb_easy_singbox.a')}
(output / 'provenance.json').write_text(json.dumps(record, indent=2) + '\n')
PY
printf 'Pinned Linux core ready: %s\n' "$output_dir"
