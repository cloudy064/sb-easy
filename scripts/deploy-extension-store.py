"""Run on the Docker host after copying the pinned .sbe bundle beside this script.
Adds only a read-only static store mount; backs up and restores Compose on failure.
"""
from pathlib import Path
import hashlib
import shutil
import subprocess
import sys
import time
import urllib.request
import yaml

bundle = Path(sys.argv[1]).resolve()
expected = sys.argv[2]
if hashlib.sha256(bundle.read_bytes()).hexdigest() != expected:
    raise SystemExit('Package digest mismatch')
project = Path('/root/workspace/sb-easy')
override = project / 'docker-compose.override.yml'
backup = override.with_name('docker-compose.override.before-store-' + str(time.time_ns()) + '.yml')
shutil.copy2(override, backup)
backup.chmod(0o600)
store = project / 'extension-store'
store.mkdir(mode=0o755, exist_ok=True)
destination = store / bundle.name
shutil.copyfile(bundle, destination)
destination.chmod(0o644)
config = yaml.safe_load(override.read_text())
volumes = config['services']['sb-easy'].setdefault('volumes', [])
target = '/app/frontend/dist/assets/store'
volumes[:] = [v for v in volumes if not (isinstance(v, str) and target in v) and not (isinstance(v, dict) and v.get('target') == target)]
volumes.append({'type': 'bind', 'source': str(store), 'target': target, 'read_only': True})
command = ['docker', 'compose', '--project-directory', str(project), '-f', str(project/'docker-compose.yml'), '-f', str(override), 'up', '-d', '--no-deps', '--no-build', '--pull', 'never', 'sb-easy']
try:
    override.write_text(yaml.safe_dump(config, sort_keys=False))
    subprocess.run(command, check=True)
    for attempt in range(30):
        try:
            with urllib.request.urlopen('http://127.0.0.1:51821/assets/store/' + bundle.name, timeout=3) as response:
                actual = hashlib.sha256(response.read()).hexdigest()
            if actual != expected:
                raise RuntimeError('Published package digest mismatch')
            print('STORE_DEPLOYED: public download matches trusted release; persistent read-only mount ready.')
            break
        except Exception:
            if attempt == 29:
                raise
            time.sleep(1)
except Exception:
    shutil.copy2(backup, override)
    subprocess.run(command, check=True)
    raise
