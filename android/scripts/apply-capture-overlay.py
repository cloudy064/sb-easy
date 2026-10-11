#!/usr/bin/env python3
"""Apply the capture extension to the pinned, pristine libbox revision."""
from pathlib import Path
import shutil
import sys
root = Path(__file__).resolve().parents[1]
source = Path(sys.argv[1]) if len(sys.argv) > 1 else root / '.libbox-src'
for file in (root / 'libbox-overlay').rglob('*.go'):
    target = source / file.relative_to(root / 'libbox-overlay')
    target.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(file, target)
service = source / 'experimental/libbox/service.go'
s = service.read_text()
if 'sbcapture.Relay' not in s:
    s = s.replace('"github.com/sagernet/sing-box/adapter"', '"github.com/sagernet/sing-box/adapter"\n "github.com/sagernet/sing-box/experimental/sbcapture"')
    marker = '\toptions.FileDescriptor = dupFd'
    assert s.count(marker) == 1
    s = s.replace(marker, '''\tif sbcapture.Enabled() {
        relayFD, relayErr := sbcapture.Relay(dupFd)
        if relayErr != nil { syscall.Close(dupFd); return nil, relayErr }
        dupFd = relayFD
    }
''' + marker)
    service.write_text(s)
route = source / 'route/route.go'
s = route.read_text()
if 'sbcapture.Classify' not in s:
    s = s.replace('"github.com/sagernet/sing-box/adapter"', '"github.com/sagernet/sing-box/adapter"\n "github.com/sagernet/sing-box/experimental/sbcapture"')
    for variable, tail in [('buffers, _', 'conn, nil'), ('_, packetBuffers', 'nil, conn')]:
        marker = f'\tselectedRule, _, {variable}, err := r.matchRule(ctx, &metadata, false, false, {tail})'
        assert s.count(marker)==1, marker
        s = s.replace(marker, '\toriginalCaptureMetadata := metadata\n\tcaptureGeneration := sbcapture.Generation()\n'+marker+'\n\tsbcapture.Classify(captureGeneration, originalCaptureMetadata, metadata)')
    route.write_text(s)

# Upgrade an earlier local overlay without discarding unrelated source edits.
s = route.read_text()
if 'captureGeneration := sbcapture.Generation()' not in s:
    s = s.replace('originalCaptureMetadata := metadata', 'originalCaptureMetadata := metadata\n\tcaptureGeneration := sbcapture.Generation()')
    s = s.replace('sbcapture.Classify(originalCaptureMetadata, metadata)', 'sbcapture.Classify(captureGeneration, originalCaptureMetadata, metadata)')
    route.write_text(s)
