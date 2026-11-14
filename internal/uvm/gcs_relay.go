//go:build windows

package uvm

import (
	"fmt"
	"net"

	"github.com/Microsoft/go-winio"
	"github.com/Microsoft/hcsshim/internal/gcs"
	"github.com/Microsoft/hcsshim/internal/protocol/guestresource"
)

// ConfigureGCSRelay replaces the direct listener before workload boot. It does
// not change the VM that executes GCS requests or its independent file shares.
func (uvm *UtilityVM) ConfigureGCSRelay(diode *UtilityVM) error {
	return uvm.configureGCSRelay(diode, func(address *winio.HvsockAddr) (net.Listener, error) {
		return winio.ListenHvsock(address)
	})
}

func (uvm *UtilityVM) configureGCSRelay(diode *UtilityVM, listen func(*winio.HvsockAddr) (net.Listener, error)) error {
	if diode == nil || diode == uvm || uvm.OS() != "linux" || diode.OS() != "linux" ||
		uvm.gcListener == nil || uvm.startInvoked.Load() || uvm.gcIoListen != nil {
		return fmt.Errorf("GCS relay requires separate Linux guests and an unstarted workload with external GCS")
	}
	listener, err := listen(&winio.HvsockAddr{
		VMID: diode.runtimeID, ServiceID: winio.VsockServiceID(guestresource.GCSRelayControlPort),
	})
	if err != nil {
		return fmt.Errorf("create diode GCS relay listener: %w", err)
	}
	if err := uvm.gcListener.Close(); err != nil {
		_ = listener.Close()
		return fmt.Errorf("close direct workload GCS listener: %w", err)
	}
	uvm.gcListener = listener
	uvm.gcIoListen = gcs.HvsockIoListen(diode.runtimeID)
	uvm.gcIoPortStart = guestresource.GCSRelayIOPortStart
	return nil
}

// gcsLogRelayListener records the one-time transfer without changing the
// existing output acceptance and shutdown lifecycle.
type gcsLogRelayListener struct{ net.Listener }

// ConfigureGCSLogRelay retargets only the unstarted workload's output listener.
// Its handler, workload attribution and completion channel retain ownership.
func (uvm *UtilityVM) ConfigureGCSLogRelay(diode *UtilityVM) error {
	return uvm.configureGCSLogRelay(diode, func(address *winio.HvsockAddr) (net.Listener, error) {
		return winio.ListenHvsock(address)
	})
}

// configureGCSLogRelay implements ConfigureGCSLogRelay with an injectable bind.
// Failed binds or old-listener closure never publish the replacement.
func (uvm *UtilityVM) configureGCSLogRelay(diode *UtilityVM, listen func(*winio.HvsockAddr) (net.Listener, error)) error {
	_, configured := uvm.outputListener.(*gcsLogRelayListener)
	if diode == nil || diode == uvm || uvm.OS() != "linux" || diode.OS() != "linux" ||
		uvm.startInvoked.Load() || configured || uvm.outputListener == nil ||
		uvm.outputHandler == nil || uvm.outputProcessingDone == nil {
		return fmt.Errorf("GCS log relay requires separate Linux guests and an unstarted workload with configured output")
	}
	listener, err := listen(&winio.HvsockAddr{
		VMID: diode.runtimeID, ServiceID: winio.VsockServiceID(guestresource.GCSRelayLogPort),
	})
	if err != nil {
		return fmt.Errorf("create diode GCS log relay listener: %w", err)
	}
	if err := uvm.outputListener.Close(); err != nil {
		_ = listener.Close()
		return fmt.Errorf("close direct workload output listener: %w", err)
	}
	uvm.outputListener = &gcsLogRelayListener{listener}
	return nil
}
