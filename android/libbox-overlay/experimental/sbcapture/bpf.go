// SPDX-License-Identifier: GPL-3.0-or-later
package sbcapture

/*
#cgo android CFLAGS: -I${SRCDIR}/pcap-source
#cgo android,arm64 LDFLAGS: ${SRCDIR}/pcap-build/arm64-v8a/libpcap.a
#cgo android,arm LDFLAGS: ${SRCDIR}/pcap-build/armeabi-v7a/libpcap.a
#cgo android,386 LDFLAGS: ${SRCDIR}/pcap-build/x86/libpcap.a
#cgo android,amd64 LDFLAGS: ${SRCDIR}/pcap-build/x86_64/libpcap.a
#cgo !android pkg-config: libpcap
#include <pcap/pcap.h>
#include <stdlib.h>
static int match_packet(struct bpf_program *program, const unsigned char *packet, unsigned int size) {
    struct pcap_pkthdr header = {0};
    header.caplen = size;
    header.len = size;
    return pcap_offline_filter(program, &header, packet) != 0;
}
*/
import "C"

import (
	"errors"
	"strings"
	"unsafe"
)

type packetFilter struct{ program C.struct_bpf_program }

func compileFilter(expression string) (*packetFilter, error) {
	if strings.TrimSpace(expression) == "" {
		return nil, nil
	}
	if len(expression) > 4096 || strings.ContainsRune(expression, 0) {
		return nil, errors.New("BPF 表达式最长 4096 字节且不能包含空字符")
	}
	handle := C.pcap_open_dead(C.DLT_RAW, 65535)
	if handle == nil {
		return nil, errors.New("无法初始化 BPF 编译器")
	}
	defer C.pcap_close(handle)
	text := C.CString(expression)
	defer C.free(unsafe.Pointer(text))
	filter := &packetFilter{}
	if C.pcap_compile(handle, &filter.program, text, 1, C.PCAP_NETMASK_UNKNOWN) != 0 {
		return nil, errors.New("BPF: " + C.GoString(C.pcap_geterr(handle)))
	}
	return filter, nil
}
func (f *packetFilter) close() {
	if f != nil {
		C.pcap_freecode(&f.program)
	}
}
func (f *packetFilter) match(packet []byte) bool {
	if f == nil {
		return true
	}
	if len(packet) == 0 {
		return false
	}
	return C.match_packet(&f.program, (*C.uchar)(unsafe.Pointer(&packet[0])), C.uint(len(packet))) != 0
}
func ValidateFilter(expression string) error {
	f, err := compileFilter(expression)
	if f != nil {
		f.close()
	}
	return err
}
