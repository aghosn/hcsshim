//go:build linux
// +build linux

package main

import (
	"strings"
	"testing"
)

func TestCalculateContainersMemoryLimit(t *testing.T) {
	tests := []struct {
		name        string
		total       uint64
		reserve     uint64
		want        int64
		wantErrText string
	}{
		{name: "subtracts reserve", total: 4096, reserve: 1024, want: 3072},
		{name: "rejects equal reserve", total: 1024, reserve: 1024, wantErrText: "must be greater"},
		{name: "rejects below reserve", total: 512, reserve: 1024, wantErrText: "must be greater"},
		{name: "rejects int64 overflow", total: uint64(1 << 63), wantErrText: "exceeds maximum"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, err := calculateContainersMemoryLimit(test.total, test.reserve)
			if test.wantErrText != "" {
				if err == nil || !strings.Contains(err.Error(), test.wantErrText) {
					t.Fatalf("expected error containing %q, got %v", test.wantErrText, err)
				}
				return
			}
			if err != nil {
				t.Fatalf("calculateContainersMemoryLimit returned error: %v", err)
			}
			if got != test.want {
				t.Fatalf("calculateContainersMemoryLimit returned %d, want %d", got, test.want)
			}
		})
	}
}

func TestGCSPeerFromCommandLine(t *testing.T) {
	for _, test := range []struct {
		command string
		peer    uint32
		bad     bool
	}{
		{"root=/dev/dm-0 init=/startup.sh", 2, false},
		{"gcs.vsock_peer_cid=4 idle=halt", 4, false},
		{"gcs.vsock_peer_cid=2", 2, false},
		{"other.gcs.vsock_peer_cid=4", 2, false},
		{"gcs.vsock_peer_cid=", 0, true},
		{"gcs.vsock_peer_cid=3", 0, true},
		{"gcs.vsock_peer_cid=4294967296", 0, true},
		{"gcs.vsock_peer_cid=4 gcs.vsock_peer_cid=2", 0, true},
	} {
		t.Run(test.command, func(t *testing.T) {
			peer, err := gcsPeerFromCommandLine(test.command)
			if (err != nil) != test.bad || peer != test.peer {
				t.Fatalf("peer=%d err=%v, want peer=%d bad=%v", peer, err, test.peer, test.bad)
			}
		})
	}
}
