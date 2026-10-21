"""Supervise the center's C HTTP server and private IP-check engine together."""
import signal
import subprocess
import sys
import time
from pathlib import Path

def main():
    stopped=False
    def stop(*_):
        nonlocal stopped
        stopped=True
    signal.signal(signal.SIGTERM,stop);signal.signal(signal.SIGINT,stop)
    children=[]
    try:
        children.append(subprocess.Popen([sys.executable,str(Path(__file__).with_name('center.py'))]))
        children.append(subprocess.Popen(sys.argv[1:]))
        while not stopped and all(p.poll() is None for p in children):time.sleep(.25)
        return 0 if stopped else next((p.returncode for p in children if p.poll() is not None),1) or 1
    finally:
        for p in reversed(children):
            if p.poll() is None:p.terminate()
        for p in children:
            try:p.wait(timeout=20)
            except subprocess.TimeoutExpired:p.kill();p.wait()

if __name__=='__main__':raise SystemExit(main())
