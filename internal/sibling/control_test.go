//go:build windows

package sibling

import (
	"context"
	"errors"
	"fmt"
	"os/exec"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestBootstrapCommandPreservesStatusOutputAndFailureDiagnostics(t *testing.T) {
	shell, err := exec.LookPath("wsl.exe")
	if err != nil {
		t.Skip("WSL shell unavailable")
	}
	for _, test := range []struct {
		name, script string
		status       int
	}{
		{"success", "printf 'bootstrap stdout\\n'", 0},
		{"explicit-exit", "printf 'relay failure on stdout\\n'; exit 7", 7},
		{"silent-guard", "[ 3 = 4 ]; printf 'must not continue\\n'", 1},
	} {
		t.Run(test.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			command := exec.CommandContext(ctx, shell, "--exec", "/bin/sh", "-ec",
				`dmesg() { printf 'fixture kernel state\n'; }; `+bootstrapCommand("fixture stage", test.script))
			var stdout, stderr strings.Builder
			command.Stdout, command.Stderr = &stdout, &stderr
			err := command.Run()
			if command.ProcessState == nil || command.ProcessState.ExitCode() != test.status {
				t.Fatalf("exit status changed: %v; stderr=%s", err, stderr.String())
			}
			if test.status == 0 {
				if stdout.String() != "bootstrap stdout\n" || strings.Contains(stderr.String(), "bootstrap failed:") {
					t.Fatalf("success output changed: stdout=%q stderr=%q", stdout.String(), stderr.String())
				}
			} else if !strings.Contains(stderr.String(), "sibling bootstrap failed: fixture stage") ||
				!strings.Contains(stderr.String(), "fixture kernel state") ||
				strings.Contains(stdout.String(), "must not continue") {
				t.Fatalf("failed bootstrap lost its diagnostics or continued: stdout=%q stderr=%q", stdout.String(), stderr.String())
			}
			if test.name == "explicit-exit" && stdout.String() != "relay failure on stdout\n" {
				t.Fatalf("failure stdout was lost: %q", stdout.String())
			}
		})
	}
}

func TestGuestOutputTailRetainsFailureAfterLongTrace(t *testing.T) {
	output := strings.Repeat("startup trace\n", 2000) + "actual failure\n"
	tail := guestOutputTail(output)
	if !strings.HasPrefix(tail, "[earlier output truncated]\n") ||
		!strings.HasSuffix(tail, "actual failure\n") || len(tail) > 16450 {
		t.Fatalf("long bootstrap trace hid its failure or exceeded the error budget: %q", tail)
	}
}

func TestExportControlAddReconcilesAmbiguousReplies(t *testing.T) {
	for _, test := range []struct {
		name     string
		writeErr error
		after    string
		listErr  error
		wantErr  bool
	}{
		{"success", nil, "7 42 1 8:16 100 0 0\n", nil, false},
		{"lost-add-reply", errors.New("lost reply"), "7 42 1 8:16 100 0 0\n", nil, false},
		{"absent", nil, "", nil, true},
		{"wrong-token", nil, "7 43 1 8:16 100 0 0\n", nil, true},
		{"retiring", nil, "7 42 1 8:16 100 1 1\n", nil, true},
		{"unconfirmed", errors.New("lost reply"), "", errors.New("GCS lost"), true},
	} {
		t.Run(test.name, func(t *testing.T) {
			reads, writes := 0, 0
			control := newExportControl(func(ctx context.Context, script string) (string, error) {
				if _, ok := ctx.Deadline(); !ok {
					t.Fatal("operation has no bound")
				}
				if strings.HasPrefix(script, "cat ") {
					reads++
					if reads == 1 {
						return "0 0 1 8:0 1000 0 1\n", nil
					}
					return test.after, test.listErr
				}
				writes++
				if !strings.Contains(script, `"7 1 42 $storage_dev"`) ||
					!strings.Contains(script, "export_add") || !strings.Contains(script, "*:0:0:3)") {
					t.Fatalf("bad RP identity or add format: %s", script)
				}
				return "", test.writeErr
			})
			err := control.Add(context.Background(), 0, 3, 7, 42, true)
			if (err != nil) != test.wantErr || reads != 2 || writes != 1 {
				t.Fatalf("Add=%v reads=%d writes=%d", err, reads, writes)
			}
		})
	}
}

func TestExportControlRemoveRequiresProvenAbsence(t *testing.T) {
	for _, test := range []struct {
		name       string
		before     string
		after      string
		writeErr   error
		readErr    error
		wantErr    bool
		wantWrites int
	}{
		{"already-absent", "", "", nil, nil, false, 0},
		{"withdrawn", "7 42 0 8:16 100 0 1", "", nil, nil, false, 1},
		{"ambiguous-but-absent", "7 42 0 8:16 100 0 1", "", errors.New("timeout"), nil, false, 1},
		{"stale-token", "7 43 0 8:16 100 0 1", "", nil, nil, true, 0},
		{"still-retiring", "7 42 0 8:16 100 0 1", "7 42 0 8:16 100 1 1", errors.New("busy"), nil, true, 1},
		{"unknown-state", "7 42 0 8:16 100 0 1", "", nil, errors.New("GCS failed"), true, 1},
		{"replaced", "7 42 0 8:16 100 0 1", "7 44 0 8:16 100 0 0", nil, nil, true, 1},
	} {
		t.Run(test.name, func(t *testing.T) {
			reads, writes := 0, 0
			control := newExportControl(func(ctx context.Context, script string) (string, error) {
				if strings.HasPrefix(script, "cat ") {
					reads++
					if reads == 1 {
						return test.before, nil
					}
					return test.after, test.readErr
				}
				writes++
				if script != "printf '%s\\n' '7 42' >"+exportParameters+"export_remove" {
					t.Fatalf("unexpected removal: %s", script)
				}
				return "", test.writeErr
			})
			ctx, cancel := context.WithTimeout(context.Background(), 15*time.Millisecond)
			defer cancel()
			err := control.Remove(ctx, 7, 42)
			if (err != nil) != test.wantErr || writes != test.wantWrites {
				t.Fatalf("Remove=%v writes=%d expectedErr=%v", err, writes, test.wantErr)
			}
		})
	}
}

func TestExportControlProtectsRootAndInvalidRPAddresses(t *testing.T) {
	control := newExportControl(func(context.Context, string) (string, error) {
		t.Fatal("invalid request reached GCS")
		return "", nil
	})
	for _, lun := range []uint8{0, 255} {
		if err := control.Add(context.Background(), 0, 1, lun, 1, true); err == nil {
			t.Fatalf("allowed root/reserved LUN %d", lun)
		}
		if err := control.Remove(context.Background(), lun, 1); err == nil {
			t.Fatalf("allowed root/reserved removal %d", lun)
		}
	}
	if err := control.Remove(context.Background(), 1, 0); err == nil {
		t.Fatal("allowed unowned export token")
	}
	if err := control.Add(context.Background(), 4, 1, 1, 1, true); err == nil {
		t.Fatal("allowed invalid RP controller")
	}
	if err := control.Add(context.Background(), 0, 64, 1, 1, true); err == nil {
		t.Fatal("allowed invalid RP LUN")
	}
}

func TestParseExportsRejectsMalformedEvidence(t *testing.T) {
	for _, text := range []string{
		"garbage", "7 1 1 8:16 100 0", "7 1 1 8 100 0 0",
		"7 1 2 8:16 100 0 0", "7 1 1 8:16 100 2 0",
		"7 1 1 8:16 nope 0 0", "7 -1 1 8:16 100 0 0",
		"255 1 1 8:16 100 0 0", "7 1 1 8:16 100 0 0\n7 2 1 8:16 100 0 0",
	} {
		if _, err := parseExports(text); err == nil {
			t.Fatalf("accepted untrustworthy export evidence %q", text)
		}
	}
	text := fmt.Sprintf("0 0 1 8:0 1000 0 1\n7 %d 0 259:16 100 1 2\n", uint64(^uint64(0)))
	got, err := parseExports(text)
	want := map[uint8]export{0: {readOnly: true}, 7: {token: ^uint64(0), retiring: true}}
	if err != nil || !reflect.DeepEqual(got, want) {
		t.Fatalf("exports=%+v err=%v", got, err)
	}
}

func TestExportControlCanceledLockDoesNotRunCommand(t *testing.T) {
	control := newExportControl(func(context.Context, string) (string, error) {
		t.Fatal("canceled operation reached GCS")
		return "", nil
	})
	control.gate <- struct{}{}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := control.Remove(ctx, 1, 1); !errors.Is(err, context.Canceled) {
		t.Fatalf("Remove=%v", err)
	}
}

func TestProviderRequiresLiveControlsAndPermanentReadOnlyRoot(t *testing.T) {
	for _, test := range []struct {
		list       string
		controlErr error
		wantErr    bool
	}{
		{"0 0 1 8:16 100 0 1", nil, false},
		{"0 0 1 8:16 100 0 1", errors.New("old kernel"), true},
		{"", nil, true},
		{"0 0 0 8:16 100 0 1", nil, true},
		{"0 0 1 8:16 100 1 1", nil, true},
	} {
		control := newExportControl(func(_ context.Context, script string) (string, error) {
			if strings.HasPrefix(script, "cat ") {
				return test.list, nil
			}
			return "", test.controlErr
		})
		if err := control.checkProvider(context.Background()); (err != nil) != test.wantErr {
			t.Fatalf("provider readiness=%v expectedFailure=%v root=%q", err, test.wantErr, test.list)
		}
	}
}
