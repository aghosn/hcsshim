//go:build linux

package transport

import "testing"

func TestVsockPeerSelection(t *testing.T) {
	relayed := &VsockTransport{PeerCID: 4, PeerPortStart: 0x40000000}
	for _, test := range []struct {
		name string
		port uint32
		peer uint32
	}{
		{"plan9 stays root", 564, 2},
		{"below control stays root", 0x3fffffff, 2},
		{"control uses diode", 0x40000000, 4},
		{"stdio uses diode", 0x60000001, 4},
	} {
		t.Run(test.name, func(t *testing.T) {
			if got := relayed.peerForPort(test.port); got != test.peer {
				t.Fatalf("peer=%d, want %d", got, test.peer)
			}
			if got := (&VsockTransport{}).peerForPort(test.port); got != 2 {
				t.Fatalf("default route changed to %d", got)
			}
		})
	}
}
