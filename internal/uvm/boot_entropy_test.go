//go:build windows

package uvm

import (
	"context"
	"errors"
	"testing"

	hcsschema "github.com/Microsoft/hcsshim/internal/hcs/schema2"
)

// protectedEntropyTestVM creates the minimum selected workload shape needed to
// exercise pre-Start entropy ownership without native HCS.
func protectedEntropyTestVM(listener *relayTestListener) *UtilityVM {
	return &UtilityVM{
		id:              "workload",
		operatingSystem: "linux",
		entropyListener: listener,
		createOpts: &OptionsLCOW{
			ConfidentialLCOWOptions: &ConfidentialLCOWOptions{SiblingRoot: true},
			SharedMemoryRegions: []LCOWSharedMemoryRegion{{
				SectionName: "protected-shape", Length: 32 << 20,
				ProtectedShared: true, ProtectedSharedControllerUri: "controller-shape",
				ProtectedSharedBackingMode: hcsschema.ProtectedSharedBackingImport,
			}},
			SiblingCommunicationEndpoints: []hcsschema.SiblingCommunicationEndpoint{{
				Role: hcsschema.SiblingCommunicationEndpointRoleWorkload,
			}},
		},
	}
}

// TestDisableBootEntropyClosesOnlySelectedListener verifies successful
// suppression closes and unpublishes only the workload listener.
func TestDisableBootEntropyClosesOnlySelectedListener(t *testing.T) {
	workloadListener := &relayTestListener{}
	controlListener := &relayTestListener{}
	outputListener := &relayTestListener{}
	diodeListener := &relayTestListener{}
	workload := protectedEntropyTestVM(workloadListener)
	workload.gcListener = controlListener
	workload.outputListener = outputListener
	diode := &UtilityVM{entropyListener: diodeListener}

	if err := workload.DisableBootEntropy(context.Background()); err != nil {
		t.Fatal(err)
	}
	if !workloadListener.closed || workload.entropyListener != nil ||
		controlListener.closed || outputListener.closed || diodeListener.closed ||
		workload.gcListener != controlListener || workload.outputListener != outputListener ||
		diode.entropyListener != diodeListener {
		t.Fatal("entropy suppression changed the wrong listener ownership")
	}
}

// TestDisableBootEntropyRejectsInvalidWorkloads verifies lifecycle, role and
// listener validation fail before mutating the existing listener.
func TestDisableBootEntropyRejectsInvalidWorkloads(t *testing.T) {
	for _, invalid := range []string{"started", "role", "ordinary", "listener"} {
		t.Run(invalid, func(t *testing.T) {
			listener := &relayTestListener{}
			workload := protectedEntropyTestVM(listener)
			switch invalid {
			case "started":
				workload.startInvoked.Store(true)
			case "role":
				workload.createOpts.(*OptionsLCOW).SiblingCommunicationEndpoints[0].Role =
					hcsschema.SiblingCommunicationEndpointRoleBackend
			case "ordinary":
				workload.createOpts.(*OptionsLCOW).SiblingRoot = false
			case "listener":
				workload.entropyListener = nil
			}

			if err := workload.DisableBootEntropy(context.Background()); err == nil {
				t.Fatal("invalid workload accepted entropy suppression")
			}
			if listener.closed {
				t.Fatal("invalid workload listener was closed")
			}
		})
	}
}

// TestDisableBootEntropyRetainsListenerOnCloseFailure verifies failed closure
// remains visible to cleanup and cannot publish suppression success.
func TestDisableBootEntropyRetainsListenerOnCloseFailure(t *testing.T) {
	failure := errors.New("close failure")
	listener := &relayTestListener{err: failure}
	workload := protectedEntropyTestVM(listener)

	err := workload.DisableBootEntropy(context.Background())
	if !errors.Is(err, failure) || workload.entropyListener != listener {
		t.Fatalf("close failure lost listener ownership: %v", err)
	}
}
