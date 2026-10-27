//go:build windows

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"testing"

	hcsschema "github.com/Microsoft/hcsshim/internal/hcs/schema2"
	hcsv2 "github.com/Microsoft/hcsshim/internal/hcs/v2"
	"github.com/Microsoft/hcsshim/internal/uvm"
	"golang.org/x/sys/windows"
)

// TestSharedMemorySectionNames covers SSH/service session zero and interactive
// sessions without changing the simple name passed to CreateFileMapping.
func TestSharedMemorySectionNames(t *testing.T) {
	for _, test := range []struct {
		name      string
		sessionID uint32
		hcsName   string
	}{
		{"session-zero", 0, `\BaseNamedObjects\hcsshim-test`},
		{"interactive", 3, `\Sessions\3\BaseNamedObjects\hcsshim-test`},
	} {
		t.Run(test.name, func(t *testing.T) {
			win32Name, hcsName, err := sharedMemorySectionNames("hcsshim-test", test.sessionID)
			if err != nil {
				t.Fatal(err)
			}
			if win32Name != "hcsshim-test" {
				t.Fatalf("Win32 section name = %q, want %q", win32Name, "hcsshim-test")
			}
			if hcsName != test.hcsName {
				t.Fatalf("HCS section name = %q, want %q", hcsName, test.hcsName)
			}
		})
	}
}

// TestProtectedSharedExchangeReceipt rejects old first-page-only output and
// mismatched role, nonce or page counts without treating diagnostics as attestation.
func TestProtectedSharedExchangeReceipt(t *testing.T) {
	const token = "00112233445566778899aabbccddeeff"
	receipt := func(participant, nonce string, pages uint64) string {
		return fmt.Sprintf("[1.234] hcs-shmem-diag: protected exchange %s %s complete; pages=%d; host sentinels unchanged\n",
			participant, nonce, pages)
	}
	for _, test := range []struct {
		name        string
		output      string
		participant string
		pages       uint64
		accept      bool
	}{
		{"single-page", receipt("a", token, 1), "a", 1, true},
		{"four-plus-tail", receipt("a", token, 5), "a", 5, true},
		{"peer", receipt("b", token, 5), "b", 5, true},
		{"two-full-batches", receipt("a", token, 8), "a", 8, true},
		{"maximum-size", receipt("a", token, 4096), "a", 4096, true},
		{"old-module", "hcs-shmem-diag: protected exchange a " + token + " complete; host sentinel unchanged\n", "a", 5, false},
		{"missing-tail", receipt("a", token, 4), "a", 5, false},
		{"first-page-only", receipt("a", token, 1), "a", 5, false},
		{"extra-digit", receipt("a", token, 50), "a", 5, false},
		{"wrong-peer", receipt("b", token, 5), "a", 5, false},
		{"wrong-token", receipt("a", strings.Repeat("f", 32), 5), "a", 5, false},
		{"missing-summary", "", "a", 5, false},
		{"trailing-error", strings.TrimSpace(receipt("a", token, 5)) + " ERROR", "a", 5, false},
		{"zero-pages", receipt("a", token, 0), "a", 0, false},
		{"too-many-pages", receipt("a", token, 4097), "a", 4097, false},
		{"third-participant", receipt("c", token, 5), "c", 5, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			err := validateProtectedExchangeReceipt(test.output, test.participant, token, test.pages)
			if (err == nil) != test.accept {
				t.Fatalf("receipt acceptance = %t, want %t: %v", err == nil, test.accept, err)
			}
		})
	}
}

// TestProtectedSharedHostProbeAllPages checks ordinary owned mappings only:
// every page must receive a sentinel and a correctly indexed evidence record.
// No native ProtectedShared operation, VM or protection claim is involved.
func TestProtectedSharedHostProbeAllPages(t *testing.T) {
	for _, pages := range []uint64{1, 5, 8} {
		t.Run(fmt.Sprint(pages), func(t *testing.T) {
			section, err := createSharedMemorySection(
				fmt.Sprintf("protected-host-probe-%d-%d", windows.GetCurrentProcessId(), pages), pages*4096)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() {
				if err := section.Close(); err != nil {
					t.Errorf("close test mapping: %v", err)
				}
			})
			var evidence bytes.Buffer
			p := &realProof{pages: pages, section: section, evidence: &proofEvidence{writer: &evidence}}
			if err := p.hostProbe(false); err != nil {
				t.Fatal(err)
			}
			lines := strings.Split(strings.TrimSpace(evidence.String()), "\n")
			if uint64(len(lines)) != pages {
				t.Fatalf("got %d host records, want %d", len(lines), pages)
			}
			for page := uint64(0); page < pages; page++ {
				offset := page*4096 + 256
				if err := section.expect(offset, []byte("HOSTKEEP")); err != nil {
					t.Fatal(err)
				}
				var record struct {
					Kind string
					Data struct {
						PageIndex, Offset, ReadBytes, WriteBytes uint64
						Negative                                 bool
					}
				}
				if err := json.Unmarshal([]byte(strings.TrimPrefix(lines[page], "PROTECTED-EVIDENCE ")), &record); err != nil {
					t.Fatal(err)
				}
				if record.Kind != "host" || record.Data.Negative || record.Data.PageIndex != page ||
					record.Data.Offset != offset || record.Data.ReadBytes != 8 || record.Data.WriteBytes != 8 {
					t.Fatalf("incorrect host evidence for page %d: %+v", page, record)
				}
			}
		})
	}
}

// TestProtectedSharedRestoredPages models only the local post-reclaim ledger on
// ordinary mappings. Scrub validation must include the last initialized page but
// not a never-initialized tail after partial failure; this is not native reclaim.
func TestProtectedSharedRestoredPages(t *testing.T) {
	for _, test := range []struct {
		name        string
		initialized uint64
		corrupt     bool
	}{
		{"first-page-prefix", 1, false},
		{"first-batch-prefix", 4, false},
		{"four-plus-tail", 5, false},
		{"corrupt-tail", 5, true},
	} {
		t.Run(test.name, func(t *testing.T) {
			const pages = uint64(5)
			section, err := createSharedMemorySection(
				fmt.Sprintf("protected-restored-%d-%s", windows.GetCurrentProcessId(), test.name), pages*4096)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() {
				if err := section.Close(); err != nil {
					t.Errorf("close test mapping: %v", err)
				}
			})
			p := &realProof{pages: pages, section: section,
				initialized: test.initialized, reclaimed: test.initialized,
				evidence: &proofEvidence{writer: io.Discard}}
			if err := p.hostProbe(false); err != nil {
				t.Fatal(err)
			}
			if err := section.write(0, make([]byte, test.initialized*4096)); err != nil {
				t.Fatal(err)
			}
			if test.corrupt {
				if err := section.write(test.initialized*4096-1, []byte{1}); err != nil {
					t.Fatal(err)
				}
			}
			result, err := p.Run(context.Background(), proofStep{Kind: "restored"})
			if (err != nil) != test.corrupt {
				t.Fatalf("restore error = %v, want failure = %t", err, test.corrupt)
			}
			wantBytes := test.initialized * 4096
			if test.corrupt {
				wantBytes -= 4096
			}
			if result.ZeroVerifiedBytes != wantBytes {
				t.Fatalf("verified %d zero bytes, want %d", result.ZeroVerifiedBytes, wantBytes)
			}
		})
	}
}

func TestSharedMemorySectionNamesRejectsPath(t *testing.T) {
	_, _, err := sharedMemorySectionNames(`Global\hcsshim-test`, 3)
	if err == nil {
		t.Fatal("expected namespaced section name to be rejected")
	}
}

func TestShellSingleQuote(t *testing.T) {
	got := shellSingleQuote("/run/module's/hcs_shmem_diag.ko")
	want := `'/run/module'"'"'s/hcs_shmem_diag.ko'`
	if got != want {
		t.Fatalf("shellSingleQuote() = %q, want %q", got, want)
	}
}

func TestSharedMemoryGuestModuleCommandConvertsGPN(t *testing.T) {
	command, err := sharedMemoryGuestModuleCommand(
		"/run/hcs_shmem_diag.ko",
		hcsschema.SharedMemoryRegion{
			SectionName: "section",
			Length:      0x100000,
		},
		hcsschema.SharedMemoryRegionInfo{
			SectionName:          "section",
			GuestPhysicalAddress: 0x20000,
		},
		"a",
		siblingEventModuleArgs(hcsschema.SiblingCommunicationRouteInfo{
			TargetVP:             0,
			TargetSINT:           3,
			EventFlagNumber:      11,
			OutboundConnectionID: 0x100015,
		}),
	)
	if err != nil {
		t.Fatal(err)
	}
	for _, expected := range []string{
		"gpa=0x20000000",
		"length=0x100000",
		"decrypted=1",
		"role='a' signal_conn=0x100015 rx_vp=0 rx_sint=3 rx_flag=11;",
	} {
		if !strings.Contains(command, expected) {
			t.Fatalf("command %q does not contain %q", command, expected)
		}
	}
}

func TestSharedMemoryGuestModuleCommandRejectsDifferentSection(t *testing.T) {
	_, err := sharedMemoryGuestModuleCommand(
		"/run/hcs_shmem_diag.ko",
		hcsschema.SharedMemoryRegion{
			SectionName: "expected",
			Length:      0x1000,
		},
		hcsschema.SharedMemoryRegionInfo{
			SectionName:          "other",
			GuestPhysicalAddress: 0x20000,
		},
		"single",
		"",
	)
	if err == nil {
		t.Fatal("expected mismatched section to fail")
	}
}

func TestSharedMemoryProofRole(t *testing.T) {
	for _, test := range []struct {
		id   string
		role string
	}{
		{id: "uvmboot-0", role: "a"},
		{id: "uvmboot-1", role: "b"},
	} {
		role, err := sharedMemoryProofRole(test.id)
		if err != nil {
			t.Fatalf("sharedMemoryProofRole(%q): %v", test.id, err)
		}
		if role != test.role {
			t.Fatalf(
				"sharedMemoryProofRole(%q) = %q, want %q",
				test.id,
				role,
				test.role,
			)
		}
	}
}

func TestSharedMemoryProofRoleRejectsUnexpectedID(t *testing.T) {
	if _, err := sharedMemoryProofRole("uvmboot-2"); err == nil {
		t.Fatal("expected unexpected UVM ID to fail")
	}
}

// TestProtectedSharedPostSealInstallDenial covers U1/U2 with fabricated cached
// receipts and typed action errors only. Exact matching denials must pass while
// success, malformed/ambiguous evidence and canceled work fail, preventing a
// negative-test false pass. It performs no native calls and proves no protection.
func TestProtectedSharedPostSealInstallDenial(t *testing.T) {
	const lease, pages = uint64(7), uint64(2)
	receipt := hcsschema.ProtectedSharedRegionInfo{
		Version: 2, Prepared: true, LeaseId: lease, PageCount: pages,
		OperationHresult: uint32(windows.ERROR_HV_OPERATION_DENIED),
	}
	wrappedDenial := fmt.Errorf("install: %w", &hcsv2.SystemError{
		ID: "c", HcsError: hcsv2.HcsError{Op: "hcs::System::Modify", Err: windows.ERROR_HV_OPERATION_DENIED},
	})
	cachedInitialized := receipt
	cachedInitialized.InitializedPages = pages
	installed := receipt
	installed.Installed = true
	success := receipt
	success.OperationHresult = 0
	successfulInstall := success
	successfulInstall.Installed = true
	wrongHRESULT := receipt
	wrongHRESULT.OperationHresult = uint32(windows.ERROR_ACCESS_DENIED)
	wrongVersion := receipt
	wrongVersion.Version = 1
	wrongLease := receipt
	wrongLease.LeaseId++
	zeroLease := receipt
	zeroLease.LeaseId = 0
	wrongPages := receipt
	wrongPages.PageCount++
	unprepared := receipt
	unprepared.Prepared = false
	removed := receipt
	removed.Prepared, removed.Removed = false, true
	nativeValid := receipt
	nativeValid.OperationResultValid = true
	nativeStatus := receipt
	nativeStatus.OperationStatus = uint32(windows.STATUS_HV_OPERATION_DENIED)
	nativeProcessed := receipt
	nativeProcessed.PagesProcessed = 1
	malformedInitialized := receipt
	malformedInitialized.InitializedPages = pages + 1
	unrelated := errors.New("transport failed")
	for _, test := range []struct {
		name       string
		dispatched bool
		actionErr  error
		receipt    *hcsschema.ProtectedSharedRegionInfo
		receiptErr error
		contextErr error
		accept     bool
	}{
		// U1: raw/wrapped typed denial and either cached initialization value
		// are equivalent; Install does not report live initialized-page state.
		{name: "exact-denial", dispatched: true, actionErr: windows.ERROR_HV_OPERATION_DENIED, receipt: &receipt, accept: true},
		{name: "wrapped-hcs-denial", dispatched: true, actionErr: wrappedDenial, receipt: &receipt, accept: true},
		{name: "cached-initialized-pages", dispatched: true, actionErr: wrappedDenial, receipt: &cachedInitialized, accept: true},
		// U2: neither failed evidence acquisition nor another action failure
		// can stand in for the precise post-seal mapping denial.
		{name: "successful-install", dispatched: true, receipt: &successfulInstall},
		{name: "successful-action-denial-cache", dispatched: true, receipt: &receipt},
		{name: "installed-despite-error", dispatched: true, actionErr: wrappedDenial, receipt: &installed},
		{name: "successful-hresult", dispatched: true, actionErr: wrappedDenial, receipt: &success},
		{name: "wrong-hresult", dispatched: true, actionErr: wrappedDenial, receipt: &wrongHRESULT},
		{name: "nil-receipt", dispatched: true, actionErr: wrappedDenial},
		{name: "wrong-version", dispatched: true, actionErr: wrappedDenial, receipt: &wrongVersion},
		{name: "wrong-lease", dispatched: true, actionErr: wrappedDenial, receipt: &wrongLease},
		{name: "zero-lease", dispatched: true, actionErr: wrappedDenial, receipt: &zeroLease},
		{name: "wrong-pages", dispatched: true, actionErr: wrappedDenial, receipt: &wrongPages},
		{name: "not-prepared", dispatched: true, actionErr: wrappedDenial, receipt: &unprepared},
		{name: "removed", dispatched: true, actionErr: wrappedDenial, receipt: &removed},
		{name: "native-result-valid", dispatched: true, actionErr: wrappedDenial, receipt: &nativeValid},
		{name: "native-status-without-frame", dispatched: true, actionErr: wrappedDenial, receipt: &nativeStatus},
		{name: "native-progress-without-frame", dispatched: true, actionErr: wrappedDenial, receipt: &nativeProcessed},
		{name: "initialized-overflow", dispatched: true, actionErr: wrappedDenial, receipt: &malformedInitialized},
		{name: "generic-access-denied", dispatched: true, actionErr: windows.ERROR_ACCESS_DENIED, receipt: &receipt},
		{name: "generic-operation-denied", dispatched: true, actionErr: hcsv2.ErrOperationDenied, receipt: &receipt},
		{name: "invalid-state", dispatched: true, actionErr: hcsv2.ErrInvalidState, receipt: &receipt},
		{name: "transport-failure", dispatched: true, actionErr: unrelated, receipt: &receipt},
		{name: "not-dispatched", actionErr: wrappedDenial, receipt: &receipt},
		{name: "independent-query-error", dispatched: true, actionErr: wrappedDenial, receipt: &receipt, receiptErr: unrelated},
		{name: "decode-error", dispatched: true, actionErr: wrappedDenial, receiptErr: errors.New("missing private field")},
		{name: "canceled-context", dispatched: true, actionErr: wrappedDenial, receipt: &receipt, contextErr: context.Canceled},
		{name: "expired-context", dispatched: true, actionErr: wrappedDenial, receipt: &receipt, contextErr: context.DeadlineExceeded},
		{name: "canceled-action", dispatched: true, actionErr: context.Canceled, receipt: &receipt},
		{name: "expired-action", dispatched: true, actionErr: context.DeadlineExceeded, receipt: &receipt},
		{name: "joined-unrelated-error", dispatched: true, actionErr: errors.Join(wrappedDenial, unrelated), receipt: &receipt},
		{name: "buried-denial", dispatched: true, actionErr: &hcsv2.HcsError{Op: "modify", Err: errors.Join(unrelated, wrappedDenial)}, receipt: &receipt},
		{name: "joined-cancellation", dispatched: true, actionErr: errors.Join(wrappedDenial, context.Canceled), receipt: &receipt},
	} {
		// Each named scenario must match its acceptance decision without
		// changing the fabricated outcome or dispatching native work.
		t.Run(test.name, func(t *testing.T) {
			outcome := uvm.ProtectedSharedModifyOutcome{
				Dispatched: test.dispatched, ActionError: test.actionErr,
				Receipt: test.receipt, ReceiptError: test.receiptErr,
			}
			err := validatePostSealInstallDenial(outcome, lease, pages, test.contextErr)
			if (err == nil) != test.accept {
				t.Fatalf("validatePostSealInstallDenial() = %v, accept = %t", err, test.accept)
			}
		})
	}
}
