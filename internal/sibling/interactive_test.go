//go:build windows

package sibling

import (
	"bytes"
	"context"
	"io"
	"net"
	"testing"
)

func TestPairShellFrameMatchesExistingAttachClient(t *testing.T) {
	kind, payload, err := readShellFrame(bytes.NewReader([]byte{1, 4, 0, 120, 0, 40, 0}))
	if err != nil || kind != 1 || !bytes.Equal(payload, []byte{120, 0, 40, 0}) {
		t.Fatalf("existing resize frame rejected: %d %v %v", kind, payload, err)
	}
	for _, frame := range [][]byte{{1}, {1, 4, 0, 120, 0}} {
		if _, _, err := readShellFrame(bytes.NewReader(frame)); err == nil {
			t.Fatal("accepted truncated attach frame")
		}
	}
}

func TestPairShellCloseDisconnectsClientsAndCancelsGuestExec(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	serverConn, clientConn := net.Pipe()
	defer clientConn.Close()
	server := &pairShells{ctx: ctx, cancel: cancel, conns: map[net.Conn]struct{}{serverConn: {}}}
	if err := server.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := clientConn.Read(make([]byte, 1)); err != io.EOF {
		t.Fatalf("client remained connected after pair close: %v", err)
	}
	if ctx.Err() != context.Canceled {
		t.Fatal("guest shell execution was not canceled")
	}
}
