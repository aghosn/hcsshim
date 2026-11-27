//go:build windows

package uvm

import (
	"errors"
	"io"
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

// TestGCSLogRelayPreservesWorkloadOwnership verifies the transport-only transfer:
// diode addressing must not replace the workload consumer or diode's own logs.
func TestGCSLogRelayPreservesWorkloadOwnership(t *testing.T) {
	direct, relayed, diodeDirect := &relayTestListener{}, &relayTestListener{}, &relayTestListener{}
	done := make(chan struct{})
	called := false
	workload := &UtilityVM{
		id: "workload", runtimeID: guid.GUID{Data1: 3},
		operatingSystem: "linux", outputListener: direct, outputProcessingDone: done,
		outputHandler: func(io.Reader) { called = true },
	}
	diode := &UtilityVM{operatingSystem: "linux", outputListener: diodeDirect, runtimeID: guid.GUID{Data1: 4}}
	// The injected bind verifies both components of the host endpoint.
	bind := func(address *winio.HvsockAddr) (net.Listener, error) {
		if address.VMID != diode.runtimeID ||
			address.ServiceID != winio.VsockServiceID(guestresource.GCSRelayLogPort) {
			t.Fatalf("wrong log endpoint: %+v", address)
		}
		return relayed, nil
	}
	if err := workload.configureGCSLogRelay(diode, bind); err != nil {
		t.Fatal(err)
	}
	workload.outputHandler(nil)
	if !called || workload.outputProcessingDone != done || !direct.closed ||
		relayed.closed || diodeDirect.closed || diode.outputListener != diodeDirect ||
		workload.id != "workload" || workload.runtimeID != (guid.GUID{Data1: 3}) {
		t.Fatal("log transfer changed output ownership")
	}
	if replacement, ok := workload.outputListener.(*gcsLogRelayListener); !ok || replacement.Listener != relayed {
		t.Fatal("log listener ownership was not transferred")
	}
	select {
	case <-done:
		t.Fatal("configuration completed output processing")
	default:
	}
	if err := workload.configureGCSLogRelay(diode, bind); err == nil {
		t.Fatal("repeated log configuration accepted")
	}
}

// TestGCSLogRelayRejectsInvalidLifecycle checks pre-Start/configured-output
// requirements before binding, preventing late listeners or no-log profiles.
func TestGCSLogRelayRejectsInvalidLifecycle(t *testing.T) {
	for _, invalid := range []string{"started", "listener", "handler", "completion", "same", "nil", "windows"} {
		t.Run(invalid, func(t *testing.T) {
			direct := &relayTestListener{}
			workload := &UtilityVM{operatingSystem: "linux", outputListener: direct,
				outputHandler: func(io.Reader) {}, outputProcessingDone: make(chan struct{})}
			diode := &UtilityVM{operatingSystem: "linux"}
			switch invalid {
			case "started":
				workload.startInvoked.Store(true)
			case "listener":
				workload.outputListener = nil
			case "handler":
				workload.outputHandler = nil
			case "completion":
				workload.outputProcessingDone = nil
			case "same":
				diode = workload
			case "nil":
				diode = nil
			case "windows":
				diode.operatingSystem = "windows"
			}
			// Invalid lifecycle must be rejected before acquiring a new listener.
			err := workload.configureGCSLogRelay(diode, func(*winio.HvsockAddr) (net.Listener, error) {
				t.Fatal("invalid configuration attempted bind")
				return nil, nil
			})
			if err == nil || direct.closed {
				t.Fatalf("invalid lifecycle changed listener: %v", err)
			}
		})
	}
}

// TestGCSLogRelaySetupFailures verifies bind/close failures remain explicit and
// release a newly acquired listener rather than publishing a successful route.
func TestGCSLogRelaySetupFailures(t *testing.T) {
	for _, failClose := range []bool{false, true} {
		direct, relayed := &relayTestListener{}, &relayTestListener{}
		failure := errors.New("log endpoint failure")
		if failClose {
			direct.err = failure
		}
		workload := &UtilityVM{operatingSystem: "linux", outputListener: direct,
			outputHandler: func(io.Reader) {}, outputProcessingDone: make(chan struct{})}
		// Fail either acquisition or the old listener's ownership handoff.
		err := workload.configureGCSLogRelay(&UtilityVM{operatingSystem: "linux"},
			func(*winio.HvsockAddr) (net.Listener, error) {
				if !failClose {
					return nil, failure
				}
				return relayed, nil
			})
		if !errors.Is(err, failure) || workload.outputListener != direct || failClose && !relayed.closed {
			t.Fatalf("failed log setup leaked or published listener: %v", err)
		}
	}
}

func (*relayTestListener) Accept() (net.Conn, error) { return nil, errors.New("unused") }
func (*relayTestListener) Addr() net.Addr            { return &net.TCPAddr{} }
func (l *relayTestListener) Close() error {
	l.closed = true
	return l.err
}

func TestGCSRelayReplacesOnlyWorkloadControl(t *testing.T) {
	direct, relayed, diodeDirect := &relayTestListener{}, &relayTestListener{}, &relayTestListener{}
	workload := &UtilityVM{operatingSystem: "linux", gcListener: direct, exitCh: make(chan struct{})}
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

func TestGCSRelayRejectsStartedWorkloadBeforeAccept(t *testing.T) {
	direct := &relayTestListener{}
	workload := &UtilityVM{operatingSystem: "linux", gcListener: direct, exitCh: make(chan struct{})}
	workload.startInvoked.Store(true)
	diode := &UtilityVM{operatingSystem: "linux"}
	err := workload.configureGCSRelay(diode, func(*winio.HvsockAddr) (net.Listener, error) {
		t.Fatal("started workload must not create a relay listener")
		return nil, nil
	})
	if err == nil || direct.closed || workload.gcListener != direct || workload.gcIoListen != nil {
		t.Fatalf("started workload configuration changed: %v", err)
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
