//go:build windows

package uvm

import (
	"errors"
	"net"
	"testing"

	"github.com/Microsoft/go-winio"
	"github.com/Microsoft/go-winio/pkg/guid"
	"github.com/Microsoft/hcsshim/internal/protocol/guestresource"
)

type relayTestListener struct {
	closed bool
	err    error
}

func (*relayTestListener) Accept() (net.Conn, error) { return nil, errors.New("unused") }
func (*relayTestListener) Addr() net.Addr            { return &net.TCPAddr{} }
func (l *relayTestListener) Close() error {
	l.closed = true
	return l.err
}

func TestGCSRelayReplacesOnlyWorkloadControl(t *testing.T) {
	direct, relayed, diodeDirect := &relayTestListener{}, &relayTestListener{}, &relayTestListener{}
	workload := &UtilityVM{operatingSystem: "linux", gcListener: direct}
	diode := &UtilityVM{operatingSystem: "linux", gcListener: diodeDirect, runtimeID: guid.GUID{Data1: 4}}
	err := workload.configureGCSRelay(diode, func(address *winio.HvsockAddr) (net.Listener, error) {
		if address.VMID != diode.runtimeID ||
			address.ServiceID != winio.VsockServiceID(guestresource.GCSRelayControlPort) {
			t.Fatalf("wrong relay endpoint: %+v", address)
		}
		return relayed, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if !direct.closed || relayed.closed || diodeDirect.closed ||
		workload.gcListener != relayed || workload.gcIoListen == nil ||
		workload.gcIoPortStart != guestresource.GCSRelayIOPortStart {
		t.Fatal("relay did not replace workload control/stdio independently of diode management")
	}
}

func TestGCSRelayFailuresDoNotSelectFallback(t *testing.T) {
	for _, failClose := range []bool{false, true} {
		direct, relayed := &relayTestListener{}, &relayTestListener{}
		failure := errors.New("endpoint failure")
		if failClose {
			direct.err = failure
		}
		workload := &UtilityVM{operatingSystem: "linux", gcListener: direct}
		diode := &UtilityVM{operatingSystem: "linux"}
		err := workload.configureGCSRelay(diode, func(*winio.HvsockAddr) (net.Listener, error) {
			if !failClose {
				return nil, failure
			}
			return relayed, nil
		})
		if !errors.Is(err, failure) || workload.gcListener != direct || workload.gcIoListen != nil {
			t.Fatalf("failed relay configuration appeared successful: %v", err)
		}
		if failClose && !relayed.closed {
			t.Fatal("failed direct listener closure leaked relay listener")
		}
	}
}
