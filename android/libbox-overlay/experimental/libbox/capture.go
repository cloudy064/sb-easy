// SPDX-License-Identifier: GPL-3.0-or-later
package libbox

import "github.com/sagernet/sing-box/experimental/sbcapture"

func ConfigureCapture(config string) error { return sbcapture.Configure(config) }
func CaptureStatus() string                { return sbcapture.Snapshot() }
func RotateCapture()                       { sbcapture.Rotate() }

func RecoverCapture(directory string) error { return sbcapture.Recover(directory) }
