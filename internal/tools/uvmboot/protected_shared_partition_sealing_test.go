//go:build windows

// Copyright (c) Microsoft Corporation. All rights reserved.

package main

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"math"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
	"unsafe"

	hcsschema "github.com/Microsoft/hcsshim/internal/hcs/schema2"
	"github.com/urfave/cli"
	"golang.org/x/sys/windows"
)

// newProtectedSharedSealTestContext applies the actual command flag definitions
// to an isolated parser without dispatching actions or acquiring resources.
// Only seal/mode/pause options are needed for these structural validation tests;
// parse failures return no usable context and remain distinct from HV errors.
func newProtectedSharedSealTestContext(t *testing.T, args ...string) (*cli.Context, error) {
	t.Helper()
	set := flag.NewFlagSet("partition-seal-options", flag.ContinueOnError)
	set.SetOutput(io.Discard)
	for _, option := range lcowCommand.Flags {
		switch option.GetName() {
		case protectedModeFlag, protectedSealFlagsFlag, protectedSealPauseFlag:
			option.Apply(set)
		}
	}
	if err := set.Parse(args); err != nil {
		return nil, err
	}
	return cli.NewContext(cli.NewApp(), set, nil), nil
}

// TestProtectedSharedPartitionSealFlagsForwarding parses decimal/hex values
// through the real uint64 flag definition and forwards zero/known/future/high
// bitmaps unchanged into every synthetic initial/repeat seal. These are
// orchestration checks, not native semantic validation or S5 probe expectations.
func TestProtectedSharedPartitionSealFlagsForwarding(t *testing.T) {
	for _, scenario := range []struct {
		input string
		want  uint64
	}{
		{"0", 0}, {"1", 1}, {"2", 2}, {"3", 3}, {"0x3", 3},
		{"256", 1 << 8}, {"0x100", 1 << 8},
		{"9223372036854775808", 1 << 63}, {"0x8000000000000000", 1 << 63},
		{"18446744073709551615", math.MaxUint64}, {"0xffffffffffffffff", math.MaxUint64},
	} {
		t.Run(scenario.input, func(t *testing.T) {
			c, err := newProtectedSharedSealTestContext(t, "-"+protectedModeFlag, "partition-seal",
				"-"+protectedSealFlagsFlag, scenario.input)
			if err != nil {
				t.Fatal(err)
			}
			if err := validateProtectedSharedSealOptions(c.String(protectedModeFlag), c.IsSet(protectedSealFlagsFlag)); err != nil {
				t.Fatal(err)
			}
			flags := c.Uint64(protectedSealFlagsFlag)
			if flags != scenario.want {
				t.Fatalf("parsed bitmap=%d, want %d", flags, scenario.want)
			}
			f := newPartitionSealFake(t)
			if err := executePartitionSealProof(context.Background(), f, 5, flags, time.Minute, false); err != nil {
				t.Fatal(err)
			}
			seals := 0
			for _, step := range f.steps {
				if step.Kind == "partition-seal" || step.Kind == "partition-seal-repeat" {
					seals++
					if step.SealFlags != scenario.want {
						t.Errorf("%s/%s bitmap=%d, want %d", step.Kind, step.Participant, step.SealFlags, scenario.want)
					}
				}
			}
			if seals != 4 {
				t.Fatalf("got %d submissions, want independent initial/repeat A/B seals", seals)
			}
		})
	}
}

// TestProtectedSharedPartitionSealFlagsSyntax rejects missing values, negative,
// overflow, fractional and nonnumeric input in the actual flag parser before
// any action/context can be dispatched. Full-width valid inputs are covered
// separately so structural rejection cannot become a semantic bitmap allowlist.
func TestProtectedSharedPartitionSealFlagsSyntax(t *testing.T) {
	for _, input := range [][]string{
		{"-" + protectedSealFlagsFlag},
		{"-" + protectedSealFlagsFlag, "-1"},
		{"-" + protectedSealFlagsFlag, "18446744073709551616"},
		{"-" + protectedSealFlagsFlag, "0x10000000000000000"},
		{"-" + protectedSealFlagsFlag, "not-a-number"},
		{"-" + protectedSealFlagsFlag, "1.5"},
	} {
		t.Run(strings.Join(input, "="), func(t *testing.T) {
			args := append([]string{"-" + protectedModeFlag, "partition-seal"}, input...)
			c, err := newProtectedSharedSealTestContext(t, args...)
			if err == nil || c != nil {
				t.Fatal("invalid uint64 syntax returned a dispatchable context")
			}
		})
	}
}

// TestProtectedSharedPartitionSealFlagsMode requires explicit presence only for
// partition-seal, and rejects supplied zero/future/high values in M1/ordinary
// modes. Both real entry points must return the option error before even pause
// filesystem validation, protecting the pre-acquisition guard. M1/ordinary with
// no option remain accepted by this pure guard and acquire nothing in this test.
func TestProtectedSharedPartitionSealFlagsMode(t *testing.T) {
	for _, scenario := range []struct {
		name, mode, value string
		supplied          bool
		wantError         string
	}{
		{"missing partition bitmap", "partition-seal", "", false, "partition-seal requires explicit protected-shared-seal-flags"},
		{"M1 omitted", "m1", "", false, ""},
		{"ordinary omitted", "", "", false, ""},
		{"M1 zero", "m1", "0", true, "protected-shared-seal-flags requires protected-shared-proof partition-seal"},
		{"M1 future", "m1", "256", true, "protected-shared-seal-flags requires protected-shared-proof partition-seal"},
		{"ordinary high", "", "0x8000000000000000", true, "protected-shared-seal-flags requires protected-shared-proof partition-seal"},
		{"ordinary maximum", "", "18446744073709551615", true, "protected-shared-seal-flags requires protected-shared-proof partition-seal"},
	} {
		t.Run(scenario.name, func(t *testing.T) {
			var args []string
			if scenario.mode != "" {
				args = append(args, "-"+protectedModeFlag, scenario.mode)
			}
			if scenario.supplied {
				args = append(args, "-"+protectedSealFlagsFlag, scenario.value)
			}
			// A later invalid pause must not mask the seal-option error or
			// cause filesystem checks before explicit presence/mode checks.
			if scenario.wantError != "" {
				args = append(args, "-"+protectedSealPauseFlag, "relative-pause")
			}
			c, err := newProtectedSharedSealTestContext(t, args...)
			if err != nil {
				t.Fatal(err)
			}
			if c.IsSet(protectedSealFlagsFlag) != scenario.supplied ||
				(!scenario.supplied && c.Uint64(protectedSealFlagsFlag) != 0) {
				t.Fatal("implicit bitmap default or incorrect explicit presence")
			}
			err = validateProtectedSharedSealOptions(c.String(protectedModeFlag), c.IsSet(protectedSealFlagsFlag))
			if proofErrorText(err) != scenario.wantError {
				t.Fatalf("option validation=%v, want %q", err, scenario.wantError)
			}
			if scenario.wantError != "" {
				for name, entry := range map[string]func(*cli.Context) error{
					"lcow": lcowCommand.Action.(func(*cli.Context) error),
					"proof": runProtectedSharedCLI,
				} {
					if err := entry(c); proofErrorText(err) != scenario.wantError {
						t.Errorf("%s entry passed early option guard: %v", name, err)
					}
				}
			}
		})
	}
}

// TestProtectedSharedHvInterfacePath requires the active hvtest interface GUID
// and returns the enumerated PnP path, not the nonexistent legacy alias. Missing,
// duplicate (including the observed ROOT/UNKNOWN instance), empty or failed
// enumeration must publish no path, preventing arbitrary device selection.
func TestProtectedSharedHvInterfacePath(t *testing.T) {
	const path = `\\?\ROOT#HVTEST#0000#{795e12bd-1d51-4e15-9f8a-4bad23d6bb4d}`
	const duplicate = `\\?\ROOT#UNKNOWN#0000#{795e12bd-1d51-4e15-9f8a-4bad23d6bb4d}`
	enumerationErr := errors.New("interface enumeration failed")
	for _, scenario := range []struct {
		name  string
		paths []string
		err   error
		want  string
	}{
		{"single active interface", []string{path}, nil, path},
		{"missing interface", nil, nil, ""},
		{"duplicate instances", []string{path, duplicate}, nil, ""},
		{"empty path", []string{""}, nil, ""},
		{"enumeration failure", []string{path}, enumerationErr, ""},
	} {
		t.Run(scenario.name, func(t *testing.T) {
			calls := 0
			got, err := protectedSharedHvInterfacePath(func(deviceID string, class *windows.GUID, flags uint32) ([]string, error) {
				calls++
				if deviceID != "" || class == nil || !strings.EqualFold(class.String(), "{795e12bd-1d51-4e15-9f8a-4bad23d6bb4d}") ||
					flags != windows.CM_GET_DEVICE_INTERFACE_LIST_PRESENT {
					t.Fatal("enumeration did not request all active hvtest interfaces")
				}
				return scenario.paths, scenario.err
			})
			if calls != 1 || got != scenario.want || (err == nil) != (scenario.want != "") {
				t.Fatalf("path=%q error=%v calls=%d, want path=%q", got, err, calls, scenario.want)
			}
			if scenario.err != nil && !errors.Is(err, scenario.err) {
				t.Fatal("enumeration error was not preserved")
			}
			if scenario.name == "duplicate instances" &&
				(!strings.Contains(err.Error(), path) || !strings.Contains(err.Error(), duplicate)) {
				t.Fatal("ambiguity error did not identify both device interfaces")
			}
		})
	}
}

// protectedSharedHvGolden decodes test-only literal wire bytes. Invalid fixture
// text fails the calling test, never a transport or native operation.
func protectedSharedHvGolden(t *testing.T, text string) []byte {
	t.Helper()
	data, err := hex.DecodeString(text)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

// TestProtectedSharedHvProbeGolden protects the unchanged native AMD64 ABI:
// tfkcontrol.h's align(16) header, tfcomponent.h component 101, hvtestcasedefs.h
// cases 35/36, winhvkt.h native sizes/padding, HvAmApi.h cache WB=6 and
// hvgdk_mini.w HV_INPUT_VTL UseTargetVtl=bit4/VTL0. Literal bytes below are
// independent of encoder offsets; a four-byte-header or packed-C client fails.
func TestProtectedSharedHvProbeGolden(t *testing.T) {
	target := protectedSharedHvTarget{
		partitionID: 0x0102030405060708, partitionIDValid: true, pageGPA: 0x1020304050607000,
	}
	for _, write := range []bool{false, true} {
		header := "23006500" // little-endian (101<<16)|35
		if write {
			header = "24006500" // little-endian (101<<16)|36
		}
		golden := header + "000000000000000000000000" + // 12-byte header padding
			"0807060504030201" + // input offset 0: actual partition ID
			"0000000000000000" + // offset 8: VP0 plus four-byte native gap
			"0071605040302010" + // offset 16: page GPA + 256
			"0800000000000000" + // offset 24: byte count 8 plus native gap
			"0610000000000000" // offset 32: WB=6, explicit VTL0=0x10
		if write {
			golden += "484f53544b4545500000000000000000" // DataBuffer[16], 8 used
		}
		frame, err := encodeProtectedSharedHvRequest(target, 256, write, [8]byte{'H', 'O', 'S', 'T', 'K', 'E', 'E', 'P'})
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(frame, protectedSharedHvGolden(t, golden)) {
			// Do not format wire buffers: the runtime version can carry data.
			t.Errorf("write=%t: native input layout differs from golden", write)
		}
	}
	if protectedSharedHvIOCTLCode != 9 || protectedSharedHvPolicyDenied != 0xc0350006 {
		t.Fatal("IOCTL or verified native policy-denial constant changed")
	}
}

// TestProtectedSharedHvProbeBounds rejects invalid/alias IDs, invalid validity,
// misaligned/overflowing GPAs and cross-page accesses before any IOCTL. The last
// valid eight-byte offset remains allowed; bounds cannot manufacture a denial.
func TestProtectedSharedHvProbeBounds(t *testing.T) {
	for _, scenario := range []string{"valid", "last eight", "invalid validity", "zero ID", "self ID", "unaligned", "overflow", "cross page", "huge offset"} {
		target := protectedSharedHvTarget{partitionID: 42, partitionIDValid: true, pageGPA: 0x1000}
		offset := uint32(256)
		switch scenario {
		case "last eight":
			offset = 4088
		case "invalid validity":
			target.partitionIDValid = false
		case "zero ID":
			target.partitionID = 0
		case "self ID":
			target.partitionID = math.MaxUint64
		case "unaligned":
			target.pageGPA++
		case "overflow":
			target.pageGPA = math.MaxUint64 - 7
		case "cross page":
			offset = 4089
		case "huge offset":
			offset = math.MaxUint32
		}
		frame, err := encodeProtectedSharedHvRequest(target, offset, false, [8]byte{})
		wantSuccess := scenario == "valid" || scenario == "last eight"
		if (err == nil) != wantSuccess || (!wantSuccess && frame != nil) {
			t.Errorf("%s: invalid bounds acceptance", scenario)
		}
	}
}

// TestProtectedSharedHvProbeNativeResults uses literal native outputs matching
// winhvkt.h Status@0/pad@4/AccessResult@8/DataBuffer@16 (32 read, 16 write).
// WinHv am.c publishes nested fields only on NT_SUCCESS; hypercall.c/winhvp.h
// and ntstatus.mc map HV_STATUS_ACCESS_DENIED=6 to c0350006, NOT c0000022
// or c0350008. Garbage nested bytes on native failure must stay invalid.
// Inline success with BytesProcessed zero must pass, intercepts must not.
func TestProtectedSharedHvProbeNativeResults(t *testing.T) {
	for _, write := range []bool{false, true} {
		for _, scenario := range []struct {
			name     string
			wire     string
			positive bool
			denial   bool
			access   bool
		}{
			{"inline zero processed", "00000000000000000000000000000000", true, false, true},
			{"processed eight", "00000000000000000000000008000000", true, false, true},
			{"unmapped", "00000000000000000100000000000000", false, false, true},
			{"read intercept", "00000000000000000200000000000000", false, false, true},
			{"write intercept", "00000000000000000300000000000000", false, false, true},
			{"native policy", "060035c000000000ffffffffffffffff", false, true, false},
			{"generic access denied", "220000c0000000000000000000000000", false, false, false},
			{"install operation denied", "080035c0000000000000000000000000", false, false, false},
			{"HRESULT access denied", "06003580000000000000000000000000", false, false, false},
			{"HRESULT install denied", "08003580000000000000000000000000", false, false, false},
			{"invalid partition", "0d0035c0000000000000000000000000", false, false, false},
			{"invalid VP", "0e0035c0000000000000000000000000", false, false, false},
			{"informational status", "01000000000000000000000000000000", false, false, true},
		} {
			wire := scenario.wire
			if !write {
				wire += "484f53544b4545500000000000000000"
			}
			output := protectedSharedHvGolden(t, wire)
			r := decodeProtectedSharedHvResult(output, uint32(len(output)), write, nil)
			if !r.nativeStatusValid || r.accessResultValid != scenario.access ||
				(r.requirePositive() == nil) != scenario.positive ||
				(r.requirePolicyDenial() == nil) != scenario.denial {
				t.Errorf("%s write=%t: incorrect native/access classification", scenario.name, write)
			}
			if !scenario.access && (r.resultCode != 0 || r.bytesProcessed != 0 || r.dataValid || r.data != [8]byte{}) {
				t.Errorf("%s: native failure interpreted unset nested output", scenario.name)
			}
			if r.dataValid != (!write && scenario.positive) {
				t.Errorf("%s: wrong data validity", scenario.name)
			}
			if r.dataValid && r.data != [8]byte{'H', 'O', 'S', 'T', 'K', 'E', 'E', 'P'} {
				t.Error("valid read did not preserve synthetic sentinel")
			}
		}
	}
}

// TestProtectedSharedHvProbeTransport uses only a narrow synchronous IOCTL fake.
// The fake asserts handle/code/sizes/alignment then returns synthetic status,
// without a driver or VM. Short/oversized frames, ACL errors and generic IOCTL
// failure cannot become a native protection pass, even with denial-looking data.
func TestProtectedSharedHvProbeTransport(t *testing.T) {
	if runtime.GOARCH != "amd64" {
		t.Skip("wire transport client is explicitly Windows AMD64 only")
	}
	transportErr := errors.New("IOCTL failed")
	for _, write := range []bool{false, true} {
		for _, scenario := range []string{"exact", "positive", "short", "oversized", "ACL", "IOCTL"} {
			calls := 0
			// The synchronous fake borrows aligned storage, fills only native
			// output, and never retains pointers or grants real HV authority.
			ioctl := func(handle windows.Handle, code uint32, input, output []byte) (uint32, error) {
				calls++
				inputSize, outputSize, id := 56, 32, uint32(0x00650023)
				if write {
					inputSize, outputSize, id = 72, 16, 0x00650024
				}
				if handle != 123 || code != 9 || len(input) != inputSize || len(output) != outputSize ||
					uintptr(unsafe.Pointer(&input[0]))%16 != 0 || uintptr(unsafe.Pointer(&output[0]))%16 != 0 ||
					binary.LittleEndian.Uint32(input[0:4]) != id {
					t.Fatal("fake received wrong handle/IOCTL/layout/alignment")
				}
				binary.LittleEndian.PutUint32(output[0:4], 0xc0350006)
				returned := uint32(outputSize)
				switch scenario {
				case "positive":
					binary.LittleEndian.PutUint32(output[0:4], 0)
					if !write {
						copy(output[16:24], []byte("HOSTKEEP"))
					}
				case "short":
					returned--
				case "oversized":
					returned++
				case "ACL":
					return returned, windows.ERROR_ACCESS_DENIED
				case "IOCTL":
					return returned, transportErr
				}
				return returned, nil
			}
			probe := &protectedSharedHvProbe{handle: 123, ioctl: ioctl}
			target := protectedSharedHvTarget{partitionID: 42, partitionIDValid: true, pageGPA: 0x1000}
			var r protectedSharedHvProbeResult
			if write {
				r = probe.write(target, 256, [8]byte{'B', 'A', 'D', 'W', 'R', 'I', 'T', 'E'})
			} else {
				r = probe.read(target, 256)
			}
			if calls != 1 || (r.requirePolicyDenial() == nil) != (scenario == "exact") ||
				(r.requirePositive() == nil) != (scenario == "positive") {
				t.Errorf("%s write=%t: transport failure misclassified", scenario, write)
			}
			if scenario != "exact" && scenario != "positive" &&
				(r.transportError == nil || r.nativeStatusValid || r.accessResultValid || r.dataValid) {
				t.Errorf("%s: failed transport published nested native fields", scenario)
			}
			if scenario == "positive" && (r.bytesProcessed != 0 || (!write &&
				(!r.dataValid || r.data != [8]byte{'H', 'O', 'S', 'T', 'K', 'E', 'E', 'P'}))) {
				t.Error("inline positive control lost zero processed or synthetic read data")
			}
			if scenario == "ACL" && !errors.Is(r.transportError, windows.ERROR_ACCESS_DENIED) {
				t.Error("transport ACL diagnostic lost")
			}
			if scenario == "IOCTL" && !errors.Is(r.transportError, transportErr) {
				t.Error("transport diagnostic lost")
			}
		}
	}
	// Buffer length as well as reported byte count is part of exact framing.
	for _, length := range []int{0, 31, 33} {
		r := decodeProtectedSharedHvResult(make([]byte, length), 32, false, nil)
		if r.transportError == nil || r.nativeStatusValid || r.requirePolicyDenial() == nil {
			t.Errorf("buffer length %d accepted as native evidence", length)
		}
	}
}

// TestProtectedSharedHvProbePrerequisites ensures unavailable clients and
// invalid targets fail before invoking the seam. Missing/closed/unsupported
// driver prerequisites must never satisfy the negative protection classifier.
func TestProtectedSharedHvProbePrerequisites(t *testing.T) {
	calls := 0
	// This fake must never run: preflight must reject each supplied client.
	ioctl := func(windows.Handle, uint32, []byte, []byte) (uint32, error) {
		calls++
		return 0, nil
	}
	for _, probe := range []*protectedSharedHvProbe{
		nil, {}, {handle: windows.InvalidHandle, ioctl: ioctl}, {handle: 123},
		{handle: 123, ioctl: ioctl},
	} {
		r := probe.read(protectedSharedHvTarget{}, 256)
		if r.transportError == nil || r.nativeStatusValid || r.requirePositive() == nil || r.requirePolicyDenial() == nil {
			t.Error("unavailable driver/target was accepted")
		}
	}
	if calls != 0 {
		t.Fatal("prerequisite failure reached IOCTL")
	}
}

// TestProtectedSharedHvChildrenGolden covers U1-a with empty and nonempty
// sequences in nonnumeric order. Literal AMD64 frames protect testcase 101/20,
// the 16-byte padded header/input and native output ID at 8, not packed offset 4.
// The synchronous fake checks alignment/zero padding without opening a driver;
// successful INVALID termination alone yields a complete, nonnil snapshot.
func TestProtectedSharedHvChildrenGolden(t *testing.T) {
	if runtime.GOARCH != "amd64" {
		t.Skip("wire transport client is explicitly Windows AMD64 only")
	}
	for _, sequence := range [][]string{
		{"0000000000000000"},
		{"0807060504030201", "2a00000000000000", "0000000000000000"},
	} {
		calls := 0
		previous := "0000000000000000"
		// The fake borrows only this call's aligned buffers. Nonzero output
		// padding proves the decoder reads the child at offset 8, not 4.
		ioctl := func(handle windows.Handle, code uint32, input, output []byte) (uint32, error) {
			if calls >= len(sequence) {
				t.Fatal("enumeration continued after INVALID")
			}
			golden := protectedSharedHvGolden(t, "14006500"+"000000000000000000000000"+
				"ffffffffffffffff"+previous)
			if handle != 123 || code != 9 || len(input) != 32 || len(output) != 16 ||
				uintptr(unsafe.Pointer(&input[0]))%16 != 0 || uintptr(unsafe.Pointer(&output[0]))%16 != 0 ||
				!bytes.Equal(input, golden) || !bytes.Equal(output, make([]byte, 16)) {
				t.Fatal("enumeration handle/code/frame/alignment/zero initialization differs from ABI")
			}
			copy(output, protectedSharedHvGolden(t, "00000000aabbccdd"+sequence[calls]))
			previous = sequence[calls]
			calls++
			return 16, nil
		}
		probe := &protectedSharedHvProbe{handle: 123, ioctl: ioctl}
		snapshot, err := probe.children(context.Background())
		if err != nil || snapshot == nil || len(snapshot) != len(sequence)-1 || calls != len(sequence) {
			t.Fatalf("complete enumeration failed: children=%d calls=%d err=%v", len(snapshot), calls, err)
		}
		for _, wireID := range sequence[:len(sequence)-1] {
			id := binary.LittleEndian.Uint64(protectedSharedHvGolden(t, wireID))
			if _, found := snapshot[id]; !found {
				t.Fatal("snapshot omitted a successfully enumerated child")
			}
		}
		if _, found := snapshot[0]; found {
			t.Fatal("INVALID became a child")
		}
	}
}

// TestProtectedSharedHvChildrenFailures covers U1-b after a valid first child:
// native failures (including junk/INVALID output), nonzero informational status,
// ACL/transport failures and short/long framing must discard all progress.
// Decoder buffer-length checks also reject malformed slices before interpreting
// output; failure must never masquerade as successful exhaustion or a usable ID.
func TestProtectedSharedHvChildrenFailures(t *testing.T) {
	if runtime.GOARCH != "amd64" {
		t.Skip("wire transport client is explicitly Windows AMD64 only")
	}
	transportErr := errors.New("enumeration IOCTL failed")
	for _, scenario := range []struct {
		name     string
		status   uint32
		id       uint64
		returned uint32
		err      error
	}{
		{"native INVALID", 0xc035000d, 0, 16, nil},
		{"native junk", 0xc035000d, math.MaxUint64, 16, nil},
		{"informational INVALID", 1, 0, 16, nil},
		{"informational child", 1, 88, 16, nil},
		{"short", 0, 0, 15, nil},
		{"long", 0, 0, 17, nil},
		{"ACL", 0, 0, 16, windows.ERROR_ACCESS_DENIED},
		{"transport", 0, 0, 16, transportErr},
	} {
		// Each case returns one valid child before the injected failure so
		// accepting partial progress cannot hide behind an empty baseline.
		t.Run(scenario.name, func(t *testing.T) {
			calls := 0
			// This synchronous fake supplies synthetic native output only;
			// its second call must be the final call on every failure path.
			ioctl := func(_ windows.Handle, _ uint32, _ []byte, output []byte) (uint32, error) {
				calls++
				if calls == 1 {
					binary.LittleEndian.PutUint64(output[8:16], 42)
					return 16, nil
				}
				if calls != 2 {
					t.Fatal("enumeration continued after a failed response")
				}
				binary.LittleEndian.PutUint32(output[0:4], scenario.status)
				binary.LittleEndian.PutUint64(output[8:16], scenario.id)
				return scenario.returned, scenario.err
			}
			probe := &protectedSharedHvProbe{handle: 123, ioctl: ioctl}
			snapshot, err := probe.children(context.Background())
			if snapshot != nil || err == nil || calls != 2 {
				t.Fatal("failed enumeration published a partial set or continued traversal")
			}
			if scenario.err != nil && !errors.Is(err, scenario.err) {
				t.Error("enumeration lost the underlying transport error")
			}
			output := make([]byte, 16)
			binary.LittleEndian.PutUint32(output[0:4], scenario.status)
			binary.LittleEndian.PutUint64(output[8:16], scenario.id)
			id, err := decodeProtectedSharedHvNextChildResult(output, scenario.returned, scenario.err)
			if id != 0 || err == nil {
				t.Fatal("failed decoder returned a usable ID")
			}
		})
	}
	for _, length := range []int{0, 15, 17} {
		id, err := decodeProtectedSharedHvNextChildResult(make([]byte, length), 16, nil)
		if id != 0 || err == nil {
			t.Errorf("output buffer length %d accepted", length)
		}
	}
}

// TestProtectedSharedHvChildrenBounds covers U1-c SELF/repeat/cycle rejection
// and the finite traversal limit. Exactly 65,536 returned children followed by
// INVALID succeeds; a 65,537th child fails without publishing partial progress.
// This guards both an off-by-one limit and unbounded changing-list traversal.
func TestProtectedSharedHvChildrenBounds(t *testing.T) {
	if runtime.GOARCH != "amd64" {
		t.Skip("wire transport client is explicitly Windows AMD64 only")
	}
	if protectedSharedHvMaxChildren != 65536 {
		t.Fatal("isolated-host traversal bound changed")
	}
	for _, scenario := range []struct {
		name     string
		ids      []uint64
		calls    int
		complete bool
	}{
		{"SELF", []uint64{42, math.MaxUint64}, 2, false},
		{"repeat", []uint64{42, 42}, 2, false},
		{"cycle", []uint64{42, 88, 42}, 3, false},
		{"limit then termination", nil, 65537, true},
		{"no termination", nil, 65537, false},
	} {
		// Each case independently bounds fake calls; no real partition list
		// or driver state is changed by the synthetic traversal.
		t.Run(scenario.name, func(t *testing.T) {
			calls := 0
			// This fake returns either the malformed sequence or increasing
			// IDs; only the complete boundary case returns terminal INVALID.
			ioctl := func(_ windows.Handle, _ uint32, _ []byte, output []byte) (uint32, error) {
				calls++
				if calls > scenario.calls {
					t.Fatal("enumeration exceeded the expected bounded calls")
				}
				id := uint64(calls)
				if scenario.ids != nil {
					id = scenario.ids[calls-1]
				} else if scenario.complete && calls == scenario.calls {
					id = 0
				}
				binary.LittleEndian.PutUint64(output[8:16], id)
				return 16, nil
			}
			probe := &protectedSharedHvProbe{handle: 123, ioctl: ioctl}
			snapshot, err := probe.children(context.Background())
			if calls != scenario.calls || (err == nil) != scenario.complete ||
				(!scenario.complete && snapshot != nil) {
				t.Fatal("malformed or excessive traversal did not fail closed at the bound")
			}
			if scenario.complete && (snapshot == nil || len(snapshot) != 65536) {
				t.Fatal("maximum valid snapshot was not published")
			}
		})
	}
}

// TestProtectedSharedHvChildrenContext covers U1-c pre-cancelled/expired
// contexts and cancellation during a child or terminal synchronous response,
// including after earlier successful progress.
// No call starts with an expired context, and cancellation observed on return
// discards even complete output. It does not claim in-flight IOCTL cancellation.
func TestProtectedSharedHvChildrenContext(t *testing.T) {
	if runtime.GOARCH != "amd64" {
		t.Skip("wire transport client is explicitly Windows AMD64 only")
	}
	for _, scenario := range []string{"cancelled", "deadline", "during child", "during termination", "after progress"} {
		ctx, cancel := context.WithCancel(context.Background())
		wantErr, wantCalls := error(context.Canceled), 0
		switch scenario {
		case "cancelled":
			cancel()
		case "deadline":
			cancel()
			ctx, cancel = context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
			wantErr = context.DeadlineExceeded
		case "after progress":
			wantCalls = 2
		default:
			wantCalls = 1
		}
		calls := 0
		// The synchronous fake cancels while borrowing the buffers and
		// still returns normally, modeling a non-cancellable native call.
		ioctl := func(_ windows.Handle, _ uint32, _ []byte, output []byte) (uint32, error) {
			calls++
			if calls > wantCalls {
				t.Fatal("enumeration invoked IOCTL after observed cancellation")
			}
			if scenario == "after progress" && calls == 1 {
				binary.LittleEndian.PutUint64(output[8:16], 42)
				return 16, nil
			}
			if scenario == "during child" {
				binary.LittleEndian.PutUint64(output[8:16], 42)
			}
			cancel()
			return 16, nil
		}
		probe := &protectedSharedHvProbe{handle: 123, ioctl: ioctl}
		snapshot, err := probe.children(ctx)
		cancel()
		if snapshot != nil || !errors.Is(err, wantErr) || calls != wantCalls {
			t.Errorf("%s: cancellation/deadline published output or issued another call", scenario)
		}
	}
}

// protectedSharedHvChildSet creates an owned synthetic snapshot for pure U2
// tests. No arguments deliberately yields a nonnil complete empty set; callers
// use nil explicitly to model an enumeration error, never a partial snapshot.
func protectedSharedHvChildSet(ids ...uint64) protectedSharedHvSnapshot {
	snapshot := make(protectedSharedHvSnapshot)
	for _, id := range ids {
		snapshot[id] = struct{}{}
	}
	return snapshot
}

// TestProtectedSharedHvUniqueAddedChild covers pure U2-a on empty/nonempty
// baselines with different insertion orders and a numerically smaller new ID.
// Sequential A/B selection must preserve A and choose distinct IDs without
// numeric ordering heuristics or changing either borrowed snapshot.
func TestProtectedSharedHvUniqueAddedChild(t *testing.T) {
	for _, baseline := range []protectedSharedHvSnapshot{
		protectedSharedHvChildSet(), protectedSharedHvChildSet(900, 700),
		protectedSharedHvChildSet(700, 900),
	} {
		afterA := protectedSharedHvChildSet(42)
		afterB := protectedSharedHvChildSet(11, 42)
		for id := range baseline {
			afterA[id] = struct{}{}
			afterB[id] = struct{}{}
		}
		a, err := uniqueProtectedSharedHvAddedChild(baseline, afterA)
		if err != nil || a != 42 {
			t.Fatalf("A correlation failed: id=%d err=%v", a, err)
		}
		b, err := uniqueProtectedSharedHvAddedChild(afterA, afterB)
		if err != nil || b != 11 || a == b {
			t.Fatalf("B correlation failed: id=%d err=%v", b, err)
		}
		if len(afterA) != len(baseline)+1 || len(afterB) != len(baseline)+2 {
			t.Fatal("selection mutated borrowed snapshot sizes")
		}
		for id := range baseline {
			if _, retained := afterA[id]; !retained {
				t.Fatal("selection mutated baseline retention")
			}
		}
		if _, retained := afterA[a]; !retained {
			t.Fatal("B baseline lost A")
		}
		if _, retained := afterB[a]; !retained {
			t.Fatal("B after snapshot lost A")
		}
	}
}

// TestProtectedSharedHvUniqueAddedChildRejects covers pure U2-b: incomplete
// snapshots, absent/ambiguous additions, disappearing baseline (including A),
// and invalid sentinel IDs anywhere in the sets must return an error and zero,
// never a guessed candidate. Orchestration/probe suppression is reserved for S3.
func TestProtectedSharedHvUniqueAddedChildRejects(t *testing.T) {
	for _, scenario := range []struct {
		name          string
		before, after protectedSharedHvSnapshot
	}{
		{"before enumeration error", nil, protectedSharedHvChildSet(42)},
		{"after enumeration error", protectedSharedHvChildSet(42), nil},
		{"no child", protectedSharedHvChildSet(), protectedSharedHvChildSet()},
		{"no addition", protectedSharedHvChildSet(42), protectedSharedHvChildSet(42)},
		{"multiple", protectedSharedHvChildSet(700), protectedSharedHvChildSet(11, 700, 42)},
		{"removed baseline", protectedSharedHvChildSet(700, 900), protectedSharedHvChildSet(700, 42)},
		{"absent known A", protectedSharedHvChildSet(42, 700), protectedSharedHvChildSet(700, 11)},
		{"INVALID candidate", protectedSharedHvChildSet(), protectedSharedHvChildSet(0)},
		{"SELF candidate", protectedSharedHvChildSet(), protectedSharedHvChildSet(math.MaxUint64)},
		{"INVALID baseline", protectedSharedHvChildSet(0), protectedSharedHvChildSet(0, 42)},
		{"SELF baseline", protectedSharedHvChildSet(math.MaxUint64), protectedSharedHvChildSet(math.MaxUint64, 42)},
	} {
		id, err := uniqueProtectedSharedHvAddedChild(scenario.before, scenario.after)
		if id != 0 || err == nil || err.Error() == "" {
			t.Errorf("%s: rejected correlation published a candidate or lacked a diagnostic", scenario.name)
		}
	}
}

// partitionSealFake records only runner steps, acquired owners and supplied
// lifecycle prefixes. It is not a VM, HCS, driver or HV-policy simulation.
// The single chosen failing step may still return valid ownership/progress;
// this protects the coordinator's consume-before-error cleanup contract.
// Discovery uses the real adapter with the existing narrow synchronous IOCTL
// fake and synthetic child lists; selected IDs are not real HV evidence.
type partitionSealFake struct {
	steps                             []partitionSealStep
	events                            []string
	initialized                       map[string]uint64
	leases                            map[string]uint64
	vmOwned                           map[string]bool
	backing                           map[string]bool
	failKind, failLifetime, failVM     string
	failPhase                         string
	failOperation                     protectedSharedHvMappingOperation
	failErr, evidenceErr              error
	scratchCleanupErr                 error
	evidenceWriteErr                  error
	evidenceBuffer                    bytes.Buffer
	cancel                            context.CancelFunc
	partial                           uint32
	unframed, uncertain, omitVM        bool
	cleanupContextInvalid, doubleClose bool
	discovery                         *realPartitionSealProof
	snapshots                         map[string][]uint64
	evidenceOnFailure                 bool
}

// newPartitionSealFake returns an empty receipt recorder with no real resource
// acquisition. Its maps track independent synthetic leases and quiet-host child
// snapshots. A buffer receives real discovery diagnostics, not native evidence.
// Non-AMD64 tests skip because the preserved enumeration transport rejects that
// architecture before invoking the synchronous IOCTL fake.
func newPartitionSealFake(t *testing.T) *partitionSealFake {
	t.Helper()
	if runtime.GOARCH != "amd64" {
		t.Skip("discovery transport client is explicitly Windows AMD64 only")
	}
	return &partitionSealFake{initialized: map[string]uint64{}, leases: map[string]uint64{},
		vmOwned: map[string]bool{}, backing: map[string]bool{},
		snapshots: map[string][]uint64{
			"snapshot-before/a": {900}, "snapshot-after/a": {42, 900},
			"snapshot-before/b": {900, 42}, "snapshot-after/b": {11, 42, 900},
		},
		discovery: &realPartitionSealProof{
			primary: &realProof{evidence: &proofEvidence{writer: &bytes.Buffer{}}, vms: map[string]*proofVM{}},
			before: map[string]protectedSharedHvSnapshot{}, after: map[string]protectedSharedHvSnapshot{},
			targets: map[string]uint64{},
		}}
}

// EvidenceError supplies the fake's sticky evidence error without changing its
// recorded ownership. Cleanup must still proceed when diagnostics have failed.
// Concrete scratch/discovery evidence errors are included, never reset.
func (f *partitionSealFake) EvidenceError() error {
	return errors.Join(f.evidenceErr, f.discovery.EvidenceError())
}

// Write implements only the fake's optional diagnostic sink. It either retains
// the supplied JSON line or reports the configured write failure; the concrete
// evidence owner, not this sink, is responsible for making that failure sticky.
func (f *partitionSealFake) Write(data []byte) (int, error) {
	if f.evidenceWriteErr != nil {
		return 0, f.evidenceWriteErr
	}
	return f.evidenceBuffer.Write(data)
}

// Run records a synchronous step and returns synthetic acquisition/progress
// facts before its configured error/cancellation. Cleanup calls are required
// to have a fresh live deadline; releases/VM closes are recorded separately so
// tests can detect forgotten partial owners, duplicate closes and unsafe frees.
// Discovery feeds synthetic enumerations through the real selection adapter;
// fake seal submissions record order and the exact requested bitmap without
// interpreting it or simulating HCS, VID or HV bitmap validity.
// Mapping steps record attempted dirty scratch only, not HV enforcement. Unmap
// cleanup exercises the concrete ledger/diagnostic helper through the existing
// IOCTL seam with synthetic success or transport failure; no VM/driver is opened.
func (f *partitionSealFake) Run(ctx context.Context, s partitionSealStep) (partitionSealResult, error) {
	f.steps = append(f.steps, s)
	cleanup := s.Kind == "teardown" || s.Kind == "remove" || s.Kind == "terminate" ||
		s.Kind == "reclaim" || s.Kind == "zero" || s.Kind == "release" || s.Kind == "close-driver" ||
		s.Kind == "scratch-cleanup"
	if cleanup {
		_, bounded := ctx.Deadline()
		f.cleanupContextInvalid = f.cleanupContextInvalid || ctx.Err() != nil || !bounded
	}
	fail := s.Kind == f.failKind && (f.failLifetime == "" || s.Lifetime == f.failLifetime) &&
		(f.failVM == "" || s.Participant == f.failVM) &&
		(f.failPhase == "" || s.MappingPhase == f.failPhase) &&
		(f.failOperation == 0 || s.MappingOperation == f.failOperation)
	r := partitionSealResult{}
	var stepErr error
	switch s.Kind {
	case "driver":
		r.DriverOwned = true
		f.events = append(f.events, "acquire-driver")
	case "open":
		f.backing[s.Lifetime] = true
		f.events = append(f.events, "acquire-"+s.Lifetime)
	case "snapshot-before", "snapshot-after":
		ids := f.snapshots[s.Kind+"/"+s.Participant]
		calls := 0
		// The existing synchronous seam supplies one synthetic child per
		// call and then INVALID. Failure/cancellation must discard the set.
		ioctl := func(_ windows.Handle, _ uint32, _ []byte, output []byte) (uint32, error) {
			if fail && f.failErr != nil {
				return 0, f.failErr
			}
			if calls < len(ids) {
				binary.LittleEndian.PutUint64(output[8:16], ids[calls])
			} else if fail && f.cancel != nil {
				f.cancel()
			}
			calls++
			return 16, nil
		}
		f.discovery.probe = &protectedSharedHvProbe{handle: 123, ioctl: ioctl}
		stepErr = f.discovery.discover(ctx, s.Participant, s.Kind == "snapshot-after")
	case "prepare":
		if !fail || !f.omitVM {
			r.VMOwned = true
			f.vmOwned[s.Participant] = true
			f.events = append(f.events, "acquire-vm-"+s.Participant)
		}
		f.leases["primary"] = 11
	case "late-prepare":
		f.leases["late"] = 22
		f.events = append(f.events, "borrow-a")
	case "hv-positive", "hv-negative":
		if f.discovery.targets[s.Participant] == 0 {
			stepErr = errors.New("fake probe lacks a validated discovery target")
		}
	case "hv-map-positive", "hv-map-negative":
		if f.discovery.scratch == nil {
			f.discovery.scratch = make(map[string]*partitionSealScratch)
		}
		// Synthetic validated ownership permits exercising cleanup bookkeeping
		// only. It is not a map result or a substitute for native policy.
		ledger := f.discovery.scratch[s.Participant]
		if ledger == nil {
			ledger = &partitionSealScratch{
				target: protectedSharedHvTarget{partitionID: f.discovery.targets[s.Participant],
					partitionIDValid: true, pageGPA: 105 * 4096},
				pages: [3]uint64{105, 106, 107}, vmID: "synthetic-" + s.Participant, runtime: "synthetic",
			}
			f.discovery.scratch[s.Participant] = ledger
		}
		ledger.dirty = true
	case "hv-unmap", "scratch-cleanup":
		// The seam observes the actual concrete unmap before any synthetic
		// teardown/remove event; errors must leave the ledger conservative.
		f.discovery.probe = &protectedSharedHvProbe{handle: 123,
			ioctl: func(_ windows.Handle, _ uint32, input, output []byte) (uint32, error) {
				if binary.LittleEndian.Uint16(input[8:10]) != uint16(protectedSharedHvUnmapScratch) ||
					binary.LittleEndian.Uint32(input[20:24]) != 3 {
					return 0, errors.New("invalid concrete scratch cleanup request")
				}
				f.events = append(f.events, "native-unmap-"+s.Participant)
				if s.Kind == "scratch-cleanup" && f.scratchCleanupErr != nil {
					return 0, f.scratchCleanupErr
				}
				if fail && f.failErr != nil {
					return 0, f.failErr
				}
				binary.LittleEndian.PutUint32(output[4:8], 3)
				return 4096, nil
			}}
		stepErr = f.discovery.cleanupScratch(ctx, s.Participant, s.MappingPhase)
	case "partition-seal", "partition-seal-repeat":
		f.events = append(f.events, "submit-"+s.Kind+"-"+s.Participant)
	case "initialize", "seal", "teardown", "reclaim":
		if s.Kind == "teardown" {
			f.events = append(f.events, "native-teardown-"+s.Lifetime)
		}
		processed := s.Count
		if fail && f.partial < processed {
			processed = f.partial
		}
		if s.Kind == "initialize" {
			f.initialized[s.Lifetime] += uint64(processed)
			f.events = append(f.events, "progress-"+s.Lifetime)
		}
		r.ControlAttempted = true
		r.proofResult = proofResult{Framed: !(fail && f.unframed), Initialized: f.initialized[s.Lifetime],
			Processed: processed, LeaseId: f.leases[s.Lifetime]}
	case "zero":
		r.ZeroVerifiedBytes = f.initialized[s.Lifetime] * 4096
	case "release":
		f.events = append(f.events, "release-"+s.Lifetime)
	case "terminate":
		if !f.vmOwned[s.Participant] {
			f.doubleClose = true
		}
		f.vmOwned[s.Participant] = false
		f.events = append(f.events, "close-vm-"+s.Participant)
	case "close-driver":
		f.events = append(f.events, "close-driver")
	}
	r.BackingOwned = f.backing[s.Lifetime]
	if r.LeaseId == 0 {
		r.LeaseId = f.leases[s.Lifetime]
	}
	if fail {
		r.Uncertain = f.uncertain
		if f.evidenceOnFailure {
			f.evidenceErr = errors.New("sticky evidence failure after synthetic submission")
		}
		if f.cancel != nil {
			f.cancel()
		}
		return r, errors.Join(stepErr, f.failErr)
	}
	return r, stepErr
}

// partitionStepPosition locates a recorded operation, optionally narrowed to a
// lease/VM, returning -1 if absent. It reads only fake diagnostics, no HV state.
func partitionStepPosition(steps []partitionSealStep, kind, lifetime, participant string) int {
	for i, s := range steps {
		if s.Kind == kind && (lifetime == "" || s.Lifetime == lifetime) &&
			(participant == "" || s.Participant == participant) {
			return i
		}
	}
	return -1
}

// partitionSealPauseFake adds only the optional operator boundary to the
// existing synthetic coordinator runner; it never pauses real guest execution.
type partitionSealPauseFake struct {
	*partitionSealFake
	pause func(context.Context) (context.Context, context.CancelFunc, error)
}

// PauseBeforeSeal invokes the test boundary without acquiring native resources.
func (f *partitionSealPauseFake) PauseBeforeSeal(ctx context.Context) (context.Context, context.CancelFunc, error) {
	return f.pause(ctx)
}

// TestProtectedSharedPartitionPauseBoundary requires a single pause after all
// positive controls/maps, before either seal. Aborting must skip sealing/exchange
// and still perform the existing independent VM/backing cleanup.
// Explicit bitmap 3 preserves this existing full-policy ordering scenario.
func TestProtectedSharedPartitionPauseBoundary(t *testing.T) {
	for _, maps := range []bool{false, true} {
		for _, abort := range []bool{false, true} {
			t.Run(fmt.Sprintf("maps=%t/abort=%t", maps, abort), func(t *testing.T) {
				f := newPartitionSealFake(t)
				pauseAt, calls := -1, 0
				stop := errors.New("operator cancelled")
				runner := &partitionSealPauseFake{partitionSealFake: f}
				runner.pause = func(ctx context.Context) (context.Context, context.CancelFunc, error) {
					calls++
					pauseAt = len(f.steps)
					if partitionStepPosition(f.steps, "hv-positive", "primary", "b") < 0 ||
						partitionStepPosition(f.steps, "partition-seal", "", "") >= 0 {
						t.Error("pause is not between positive controls and partition sealing")
					}
					if maps && (f.steps[pauseAt-1].Kind != "hv-unmap" ||
						f.steps[pauseAt-1].Participant != "b" || f.steps[pauseAt-1].MappingPhase != "pre-seal") {
						t.Error("pre-seal map controls did not finish before pausing")
					}
					if abort {
						return ctx, func() {}, stop
					}
					return ctx, func() {}, nil
				}
				err := executePartitionSealProof(context.Background(), runner, 5, 3, time.Minute, maps)
				sealAt := partitionStepPosition(f.steps, "partition-seal", "", "")
				if calls != 1 || errors.Is(err, stop) != abort || (!abort && err != nil) ||
					(abort && sealAt != -1) || (!abort && sealAt != pauseAt) {
					t.Fatalf("calls=%d pause=%d seal=%d error=%v", calls, pauseAt, sealAt, err)
				}
				if f.cleanupContextInvalid || partitionStepPosition(f.steps, "terminate", "", "b") < 0 ||
					partitionStepPosition(f.steps, "release", "primary", "") < 0 ||
					(abort && partitionStepPosition(f.steps, "exchange", "", "") >= 0) {
					t.Fatal("pause changed cleanup or allowed exchange after abort")
				}
			})
		}
	}
}

// TestProtectedSharedPartitionPauseBudget lets the original deadline expire
// while the operator gate is waiting. Continue must return a live bounded
// context; abort must fail instead of allowing the caller to submit seals.
func TestProtectedSharedPartitionPauseBudget(t *testing.T) {
	for _, decision := range []string{"continue", "abort"} {
		t.Run(decision, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "seal")
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			type result struct {
				ctx    context.Context
				cancel context.CancelFunc
				err    error
			}
			done := make(chan result, 1)
			go func() {
				resumed, stop, err := waitPartitionSealResume(ctx, path, &proofEvidence{writer: &bytes.Buffer{}})
				done <- result{resumed, stop, err}
			}()
			// A deferred abort also releases the waiter on an assertion failure.
			defer func() {
				_ = os.WriteFile(path+".resume.tmp", []byte("abort"), 0600)
				_ = os.Rename(path+".resume.tmp", path+".resume")
			}()
			until := time.Now().Add(5 * time.Second)
			for {
				if _, err := os.Stat(path + ".ready"); err == nil {
					break
				} else if !os.IsNotExist(err) || time.Now().After(until) {
					t.Fatalf("ready marker missing: %v", err)
				}
				time.Sleep(10 * time.Millisecond)
			}
			<-ctx.Done()
			select {
			case r := <-done:
				r.cancel()
				t.Fatalf("gate returned before an operator decision: %v", r.err)
			default:
			}
			if err := os.WriteFile(path+".resume.tmp", []byte(decision), 0600); err != nil {
				t.Fatal(err)
			}
			if err := os.Rename(path+".resume.tmp", path+".resume"); err != nil {
				t.Fatal(err)
			}
			select {
			case r := <-done:
				defer r.cancel()
				if decision == "abort" {
					if r.err == nil {
						t.Fatal("abort accepted as continuation")
					}
				} else if deadline, bounded := r.ctx.Deadline(); r.err != nil || r.ctx.Err() != nil ||
					!bounded || time.Until(deadline) <= 0 || time.Until(deadline) > time.Second {
					t.Fatalf("forward budget did not resume: %v, %v", r.err, r.ctx.Err())
				}
			case <-time.After(5 * time.Second):
				t.Fatal("gate did not consume the operator decision")
			}
		})
	}
}

// TestProtectedSharedPartitionOrder records a five-page 4+1 run. Both installed
// VM page-lock barriers must precede controls and seals, both completed seals
// and repeats precede negatives/late acquisition, and late remains unsealed
// and alive through fresh primary exchange. Separate cleanup must zero-check
// both leases before release and close exactly the two independently owned VMs.
// This protects orchestration only; synthetic steps do not prove HV behavior.
// U2-c brackets each entire prepare boundary with discovery before B starts;
// U3-a omits identity actions and requires fresh initial/repeat submissions.
// Explicit bitmap 3 keeps these original full-policy expectations unchanged.
func TestProtectedSharedPartitionOrder(t *testing.T) {
	f := newPartitionSealFake(t)
	if err := executePartitionSealProof(context.Background(), f, 5, 3, time.Minute, false); err != nil {
		t.Fatal(err)
	}
	expected := []string{
		"driver//", "open/primary/", "seed/primary/",
		"snapshot-before//a", "prepare/primary/a", "snapshot-after//a",
		"snapshot-before//b", "prepare/primary/b", "snapshot-after//b",
		"initialize/primary/", "initialize/primary/", "install/primary/a", "install/primary/b",
		"seal/primary/", "seal/primary/",
		"hv-positive/primary/a", "hv-positive/primary/b",
		"partition-seal/primary/a", "partition-seal/primary/b",
		"partition-seal-repeat/primary/a", "partition-seal-repeat/primary/b",
		"hv-negative/primary/a", "hv-negative/primary/b",
		"open/late/", "seed/late/", "late-prepare/late/a", "initialize/late/",
		"late-install-denial/late/a", "exchange/primary/",
		"teardown/primary/", "teardown/primary/", "remove/primary/a", "remove/primary/b",
		"teardown/late/", "remove/late/a", "terminate//a", "terminate//b",
		"reclaim/late/", "zero/late/", "release/late/",
		"reclaim/primary/", "reclaim/primary/", "zero/primary/", "release/primary/", "close-driver//",
	}
	if len(f.steps) != len(expected) {
		t.Fatalf("got %d steps, expected %d", len(f.steps), len(expected))
	}
	for i, s := range f.steps {
		if got := s.Kind + "/" + s.Lifetime + "/" + s.Participant; got != expected[i] {
			t.Errorf("step %d: %s, expected %s", i, got, expected[i])
		}
		if s.Kind == "initialize" || s.Kind == "seal" || s.Kind == "teardown" || s.Kind == "reclaim" {
			wantCount := uint32(1)
			if s.Lifetime == "primary" && s.Index == 0 {
				wantCount = 4
			}
			if s.Count != wantCount || (s.Index != 0 && s.Index != 4) {
				t.Errorf("step %d: incorrect 4+1 lifecycle range", i)
			}
		}
	}
	if strings.Count(strings.Join(f.events, ","), "acquire-vm-") != 2 ||
		strings.Count(strings.Join(f.events, ","), "close-vm-") != 2 ||
		f.cleanupContextInvalid || f.doubleClose {
		t.Fatal("VM ownership or independent cleanup contract violated")
	}
	if f.discovery.targets["a"] != 42 || f.discovery.targets["b"] != 11 ||
		len(f.discovery.before["b"]) != 2 || len(f.discovery.after["b"]) != 3 {
		t.Fatal("sequential discovery lost validated snapshots or distinct diagnostic targets")
	}
	for _, kind := range []string{"partition-seal", "partition-seal-repeat"} {
		for _, id := range []string{"a", "b"} {
			if strings.Count(strings.Join(f.events, ","), "submit-"+kind+"-"+id) != 1 {
				t.Error("initial/repeat seal was not independently submitted")
			}
		}
	}
}

// TestProtectedSharedPartitionDiscoveryFailures covers U2-a/b/c using synthetic
// child lists through the existing IOCTL fake and the real discovery adapter.
// Enumeration/selection errors and cancellation must publish no failed target,
// stop B/probes as applicable, and independently clean every acquired VM and
// known backing. Prepare errors still return ownership before cleanup decisions.
// These order/correlation assertions are not real HCS or hypervisor evidence.
// Explicit bitmap 3 retains the original full-policy failure scenario.
func TestProtectedSharedPartitionDiscoveryFailures(t *testing.T) {
	for _, scenario := range []struct {
		name, kind, id      string
		override            bool
		ids                 []uint64
		operationErr, cancel bool
		wantA, wantB         bool
	}{
		{"A before enumeration error", "snapshot-before", "a", false, nil, true, false, false, false},
		{"A before cancelled", "snapshot-before", "a", false, nil, false, true, false, false},
		{"A acquired prepare error", "prepare", "a", false, nil, true, false, true, false},
		{"A acquired prepare cancelled", "prepare", "a", false, nil, false, true, true, false},
		{"A after enumeration error", "snapshot-after", "a", false, nil, true, false, true, false},
		{"A after cancelled", "snapshot-after", "a", false, nil, false, true, true, false},
		{"A no addition", "snapshot-after", "a", true, []uint64{900}, false, false, true, false},
		{"A ambiguous", "snapshot-after", "a", true, []uint64{900, 42, 43}, false, false, true, false},
		{"A removed baseline", "snapshot-after", "a", true, []uint64{42}, false, false, true, false},
		{"B before enumeration error", "snapshot-before", "b", false, nil, true, false, true, false},
		{"B before cancelled", "snapshot-before", "b", false, nil, false, true, true, false},
		{"B baseline missing A", "snapshot-before", "b", true, []uint64{900}, false, false, true, false},
		{"B acquired prepare error", "prepare", "b", false, nil, true, false, true, true},
		{"B acquired prepare cancelled", "prepare", "b", false, nil, false, true, true, true},
		{"B after enumeration error", "snapshot-after", "b", false, nil, true, false, true, true},
		{"B after cancelled", "snapshot-after", "b", false, nil, false, true, true, true},
		{"B after missing A", "snapshot-after", "b", true, []uint64{900, 11}, false, false, true, true},
		{"B no distinct addition", "snapshot-after", "b", true, []uint64{42, 900}, false, false, true, true},
		{"B ambiguous", "snapshot-after", "b", true, []uint64{11, 42, 900, 12}, false, false, true, true},
		{"B removed baseline", "snapshot-after", "b", true, []uint64{11, 42}, false, false, true, true},
	} {
		// Isolate each failed boundary so later acquisitions cannot mask a
		// missing owner or a target accidentally retained after an error.
		t.Run(scenario.name, func(t *testing.T) {
			f := newPartitionSealFake(t)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			f.failKind, f.failVM = scenario.kind, scenario.id
			if scenario.override {
				f.snapshots[scenario.kind+"/"+scenario.id] = scenario.ids
			}
			if scenario.operationErr {
				f.failErr = errors.New("synthetic discovery/preparation failure")
			}
			if scenario.cancel {
				f.cancel = cancel
			}
			err := executePartitionSealProof(ctx, f, 5, 3, time.Minute, false)
			if err == nil || (scenario.operationErr && !errors.Is(err, f.failErr)) ||
				(scenario.cancel && !errors.Is(err, context.Canceled)) {
				t.Fatal("discovery/acquisition failure was not retained")
			}
			if f.discovery.targets[scenario.id] != 0 || f.discovery.after[scenario.id] != nil {
				t.Error("failed discovery published a usable candidate or after snapshot")
			}
			if scenario.kind != "prepare" && f.discovery.before[scenario.id] != nil {
				t.Error("failed discovery retained its baseline for accidental reuse")
			}
			if scenario.id == "b" && f.discovery.targets["a"] != 42 {
				t.Error("B failure discarded independently validated A diagnostics")
			}
			if partitionStepPosition(f.steps, "hv-positive", "", "") >= 0 ||
				partitionStepPosition(f.steps, "hv-negative", "", "") >= 0 ||
				partitionStepPosition(f.steps, "open", "late", "") >= 0 {
				t.Error("discovery failure allowed GPA probing or late acquisition")
			}
			failed := partitionStepPosition(f.steps, scenario.kind, "", scenario.id)
			if failed < 0 {
				t.Fatal("configured discovery boundary was skipped")
			}
			for _, s := range f.steps[failed+1:] {
				switch s.Kind {
				case "remove", "terminate", "release", "close-driver":
				default:
					t.Errorf("forward work continued after discovery failure: %s", s.Kind)
				}
			}
			for id, owned := range map[string]bool{"a": scenario.wantA, "b": scenario.wantB} {
				closed := partitionStepPosition(f.steps, "terminate", "", id) >= 0
				if closed != owned {
					t.Errorf("%s: cleanup did not match acquired VM ownership", id)
				}
				if owned && partitionStepPosition(f.steps, "remove", "primary", id) < 0 {
					t.Errorf("%s: acquired prepared owner was not removed independently", id)
				}
			}
			if partitionStepPosition(f.steps, "release", "primary", "") < 0 ||
				partitionStepPosition(f.steps, "close-driver", "", "") < 0 ||
				f.cleanupContextInvalid || f.doubleClose {
				t.Error("discovery failure lost known-safe backing/driver or cleanup context")
			}
		})
	}
}

// TestProtectedSharedPartitionPartialAcquisition cancels/errors at acquired VM,
// partial primary initialization, and late acquisition/preparation/initialization.
// Returned owners and valid prefixes must enter cleanup before forward work
// stops. Fresh cleanup must still remove late's borrowed owner, close A only
// once, and use each lease's actual prefix (including zero/no-init cases).
// Explicit bitmap 3 retains these existing full-policy cleanup expectations.
func TestProtectedSharedPartitionPartialAcquisition(t *testing.T) {
	for _, scenario := range []struct {
		name, kind, lifetime, vm string
		cancel                  bool
		partial                 uint32
		wantPrimary, wantLate    uint64
	}{
		{"acquired A then cancel", "prepare", "primary", "a", true, 0, 0, 0},
		{"acquired B then error", "prepare", "primary", "b", false, 0, 0, 0},
		{"partial init then cancel", "initialize", "primary", "", true, 2, 2, 0},
		{"partial init then error", "initialize", "primary", "", false, 2, 2, 0},
		{"late open then cancel", "open", "late", "", true, 0, 5, 0},
		{"late owner then error", "late-prepare", "late", "a", false, 0, 5, 0},
		{"late initialized then cancel", "initialize", "late", "", true, 1, 5, 1},
		{"late install unexpected result", "late-install-denial", "late", "a", false, 0, 5, 1},
	} {
		// Each subtest owns a fresh recorder/context. No native resource or
		// protection result is fabricated; only step receipts are supplied.
		t.Run(scenario.name, func(t *testing.T) {
			f := newPartitionSealFake(t)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			f.failKind, f.failLifetime, f.failVM = scenario.kind, scenario.lifetime, scenario.vm
			f.partial = scenario.partial
			f.failErr = errors.New("operation failed after acquisition/progress")
			if scenario.cancel {
				f.cancel, f.failErr = cancel, nil
			}
			if err := executePartitionSealProof(ctx, f, 5, 3, time.Minute, false); err == nil {
				t.Fatal("failed/cancelled forward operation passed")
			}
			failed := partitionStepPosition(f.steps, scenario.kind, scenario.lifetime, scenario.vm)
			for _, s := range f.steps[failed+1:] {
				switch s.Kind {
				case "teardown", "remove", "terminate", "reclaim", "zero", "release", "close-driver":
				default:
					t.Errorf("forward work continued after failure: %s", s.Kind)
				}
			}
			for name, initialized := range map[string]uint64{"primary": scenario.wantPrimary, "late": scenario.wantLate} {
				var teardown, reclaim uint64
				for _, s := range f.steps {
					if s.Lifetime == name && s.Kind == "teardown" {
						teardown += uint64(s.Count)
					}
					if s.Lifetime == name && s.Kind == "reclaim" {
						reclaim += uint64(s.Count)
					}
				}
				if teardown != initialized || reclaim != initialized {
					t.Errorf("%s: cleanup discarded returned progress: teardown=%d reclaim=%d expected=%d",
						name, teardown, reclaim, initialized)
				}
			}
			if partitionStepPosition(f.steps, "terminate", "", "a") < 0 ||
				partitionStepPosition(f.steps, "release", "primary", "") < 0 {
				t.Error("acquired A/primary was lost on error/cancellation")
			}
			if scenario.lifetime == "late" && partitionStepPosition(f.steps, "release", "late", "") < 0 {
				t.Error("known late acquisition was not cleaned")
			}
			if scenario.kind == "late-prepare" || scenario.wantLate != 0 {
				if partitionStepPosition(f.steps, "remove", "late", "a") < 0 {
					t.Error("prepared unmapped late owner was not explicitly removed")
				}
			}
			if f.cleanupContextInvalid || f.doubleClose {
				t.Error("cleanup inherited cancellation or duplicated VM ownership")
			}
		})
	}
}

// TestProtectedSharedPartitionRetainsUncertain supplies unknown initialization/
// preparation or failed detach, VM termination and partial reclaim receipts.
// The affected lifetime must never be released, while independent safe owners
// still get cleanup. In particular late uncertainty cannot be mistaken for
// zero native initialization work or independent ownership of VM A.
// Explicit bitmap 3 preserves the existing full-policy retention scenario.
func TestProtectedSharedPartitionRetainsUncertain(t *testing.T) {
	for _, scenario := range []struct {
		name, kind, lifetime, vm  string
		unframed, uncertain      bool
		retainPrimary, retainLate bool
	}{
		{"unknown primary init", "initialize", "primary", "", true, false, true, false},
		{"unknown primary page lock", "seal", "primary", "", true, false, true, false},
		{"unknown late owner", "late-prepare", "late", "a", false, true, false, true},
		{"unknown late init", "initialize", "late", "", true, false, false, true},
		{"primary detach failure", "remove", "primary", "a", false, false, true, false},
		{"late detach failure", "remove", "late", "a", false, false, false, true},
		{"A termination failure", "terminate", "", "a", false, false, true, true},
		{"B termination failure", "terminate", "", "b", false, false, true, false},
		{"primary partial reclaim", "reclaim", "primary", "", false, false, true, false},
		{"late partial reclaim", "reclaim", "late", "", false, false, false, true},
		{"late zero failure", "zero", "late", "", false, false, false, true},
	} {
		// Failure is injected only into this unit recorder, not the lab
		// coordinator/native implementation or partition sealing primitive.
		t.Run(scenario.name, func(t *testing.T) {
			f := newPartitionSealFake(t)
			f.failKind, f.failLifetime, f.failVM = scenario.kind, scenario.lifetime, scenario.vm
			f.unframed, f.uncertain = scenario.unframed, scenario.uncertain
			f.failErr = errors.New("uncertain or failed cleanup operation")
			if err := executePartitionSealProof(context.Background(), f, 5, 3, time.Minute, false); err == nil {
				t.Fatal("uncertain/failed operation passed")
			}
			for name, retain := range map[string]bool{"primary": scenario.retainPrimary, "late": scenario.retainLate} {
				released := partitionStepPosition(f.steps, "release", name, "") >= 0
				acquired := partitionStepPosition(f.steps, "open", name, "") >= 0
				if retain && released {
					t.Errorf("%s backing released after uncertain/failed progress", name)
				}
				if acquired && !retain && !released {
					t.Errorf("independent safe %s lifetime was not cleaned", name)
				}
			}
			if f.cleanupContextInvalid || f.doubleClose {
				t.Error("unsafe VM or cleanup-context ownership")
			}
		})
	}
}

// TestProtectedSharedPartitionPartialSealing covers U3-b operation errors,
// cancellation and sticky evidence failure at each initial/repeat A/B seal.
// Every synthetic submission must stop later forward work on failure while
// preserving independent two-VM teardown/reclaim/release. Neither cancellation
// nor a fake submission proves native sealing had no effect or produced a receipt.
// Explicit bitmap 3 preserves these original full-policy failure boundaries.
func TestProtectedSharedPartitionPartialSealing(t *testing.T) {
	for _, kind := range []string{"partition-seal", "partition-seal-repeat"} {
		for _, id := range []string{"a", "b"} {
			for _, failure := range []string{"operation error", "cancellation", "sticky evidence"} {
				// Each independent recorder models a completed attempt and
				// its failure, not native success or the partition's state.
				t.Run(kind+"/"+id+"/"+failure, func(t *testing.T) {
					f := newPartitionSealFake(t)
					ctx, cancel := context.WithCancel(context.Background())
					defer cancel()
					f.failKind, f.failVM = kind, id
					switch failure {
					case "operation error":
						f.failErr = errors.New("synthetic seal operation failed")
					case "cancellation":
						f.cancel = cancel
					case "sticky evidence":
						f.evidenceOnFailure = true
					}
					err := executePartitionSealProof(ctx, f, 5, 3, time.Minute, false)
					if err == nil || (f.failErr != nil && !errors.Is(err, f.failErr)) ||
						(failure == "cancellation" && !errors.Is(err, context.Canceled)) ||
						(failure == "sticky evidence" && !errors.Is(err, f.evidenceErr)) {
						t.Fatal("seal failure/cancellation/evidence error was not retained")
					}
					failed := partitionStepPosition(f.steps, kind, "", id)
					if failed < 0 {
						t.Fatal("failed seal submission was skipped")
					}
					for _, s := range f.steps[failed+1:] {
						switch s.Kind {
						case "teardown", "remove", "terminate", "reclaim", "zero", "release", "close-driver":
						default:
							t.Errorf("forward work continued after seal failure: %s", s.Kind)
						}
					}
					for _, owner := range []string{"a", "b"} {
						if partitionStepPosition(f.steps, "terminate", "", owner) < 0 ||
							partitionStepPosition(f.steps, "remove", "primary", owner) < 0 {
							t.Error("seal failure lost independent VM/region cleanup")
						}
					}
					if partitionStepPosition(f.steps, "release", "primary", "") < 0 ||
						partitionStepPosition(f.steps, "close-driver", "", "") < 0 ||
						f.cleanupContextInvalid || f.doubleClose {
						t.Error("seal failure prevented known-safe independent cleanup")
					}
				})
			}
		}
	}
}

// TestProtectedSharedPartitionNoPhantomOwner rejects invalid bounds without
// dispatch and exercises failed acquisition with no VM returned. Only actually
// returned VM ownership permits termination; sticky evidence still closes an
// acquired driver even though no backing or further forward work is allowed.
// Explicit bitmap 3 changes neither acquisition bounds nor cleanup authority.
func TestProtectedSharedPartitionNoPhantomOwner(t *testing.T) {
	for _, pages := range []uint64{0, 4097} {
		f := newPartitionSealFake(t)
		if err := executePartitionSealProof(context.Background(), f, pages, 3, time.Minute, false); err == nil || len(f.steps) != 0 {
			t.Error("invalid page bound acquired resources")
		}
	}
	f := newPartitionSealFake(t)
	f.failKind, f.failVM, f.omitVM, f.failErr = "prepare", "a", true, errors.New("no returned VM")
	if err := executePartitionSealProof(context.Background(), f, 1, 3, time.Minute, false); err == nil ||
		partitionStepPosition(f.steps, "terminate", "", "") >= 0 || f.doubleClose {
		t.Error("failed acquisition invented a VM owner")
	}
	f = newPartitionSealFake(t)
	f.evidenceErr = errors.New("evidence write failed")
	if err := executePartitionSealProof(context.Background(), f, 1, 3, time.Minute, false); err == nil ||
		partitionStepPosition(f.steps, "open", "", "") >= 0 ||
		partitionStepPosition(f.steps, "close-driver", "", "") < 0 {
		t.Error("sticky evidence failure hid acquisition or allowed forward progress")
	}
}

// TestProtectedSharedPartitionNamedPreparation keeps M1's single exact primary
// response requirement and permits only A's named metadata-only extra slot.
// Native ordinary-hidden slots may be omitted; an exposed/reversed property
// must not select late as primary. Duplicate/missing primary, unexpected or
// already-protected slots must fail without claiming ownership.
func TestProtectedSharedPartitionNamedPreparation(t *testing.T) {
	primary := hcsschema.SharedMemoryRegionInfo{SectionName: "primary", GuestPhysicalAddress: 10}
	late := hcsschema.SharedMemoryRegionInfo{SectionName: "late", GuestPhysicalAddress: 20}
	for _, scenario := range []struct {
		name, slot, id string
		regions        []hcsschema.SharedMemoryRegionInfo
		success        bool
	}{
		{"M1 one", "", "a", []hcsschema.SharedMemoryRegionInfo{primary}, true},
		{"M1 rejects extra", "", "a", []hcsschema.SharedMemoryRegionInfo{primary, late}, false},
		{"A reverse order", "late", "a", []hcsschema.SharedMemoryRegionInfo{late, primary}, true},
		{"B stays single", "late", "b", []hcsschema.SharedMemoryRegionInfo{primary}, true},
		{"B rejects extra", "late", "b", []hcsschema.SharedMemoryRegionInfo{primary, late}, false},
		{"duplicate primary", "late", "a", []hcsschema.SharedMemoryRegionInfo{primary, primary}, false},
		{"missing primary", "late", "a", []hcsschema.SharedMemoryRegionInfo{late, late}, false},
		{"native hidden omitted", "late", "a", []hcsschema.SharedMemoryRegionInfo{primary}, true},
		{"protected late", "late", "a", []hcsschema.SharedMemoryRegionInfo{primary,
			{SectionName: "late", ProtectedShared: &hcsschema.ProtectedSharedRegionInfo{}}}, false},
	} {
		found, err := selectProtectedProofRegion(scenario.regions, "primary", scenario.slot, scenario.id)
		if (err == nil) != scenario.success || (err == nil && (found == nil || found.GuestPhysicalAddress != 10)) {
			t.Errorf("%s: incorrect named region selection", scenario.name)
		}
	}
}

// TestProtectedSharedPartitionMappingOptions checks opt-in containment without
// acquiring resources. Only plain partition-seal with eligible aligned section
// bytes passes; disabled inputs are deliberately uninterpreted so ordinary/M1/
// SNP handling and otherwise-supported sizes remain the existing paths' job.
// The coordinator bound check supplies bitmap 3 explicitly, not as a default.
func TestProtectedSharedPartitionMappingOptions(t *testing.T) {
	for _, scenario := range []struct {
		name, mode string
		snp        bool
		size       uint64
		valid      bool
	}{
		{"no proof", "", false, 5 * 4096, false},
		{"ordinary", "ordinary", false, 5 * 4096, false},
		{"m1", "m1", false, 5 * 4096, false},
		{"SNP", "partition-seal", true, 5 * 4096, false},
		{"zero", "partition-seal", false, 0, false},
		{"unaligned", "partition-seal", false, 4097, false},
		{"one page", "partition-seal", false, 4096, true},
		{"default", "partition-seal", false, 5 * 4096, true},
		{"exact padding", "partition-seal", false, 509 * 4096, true},
		{"two padding", "partition-seal", false, 510 * 4096, false},
		{"one padding", "partition-seal", false, 511 * 4096, false},
		{"no padding", "partition-seal", false, 512 * 4096, false},
		{"next reservation", "partition-seal", false, 513 * 4096, true},
		{"last eligible", "partition-seal", false, 4093 * 4096, true},
		{"maximum no padding", "partition-seal", false, 4096 * 4096, false},
		{"too large", "partition-seal", false, 4097 * 4096, false},
		{"overflow bytes", "partition-seal", false, math.MaxUint64, false},
	} {
		// The same input with the option off must never impose a new rule.
		t.Run(scenario.name, func(t *testing.T) {
			if err := validateProtectedSharedMapOptions(true, scenario.mode, scenario.snp, scenario.size); (err == nil) != scenario.valid {
				t.Fatalf("enabled validation=%v, expected valid=%t", err, scenario.valid)
			}
			if err := validateProtectedSharedMapOptions(false, scenario.mode, scenario.snp, scenario.size); err != nil {
				t.Fatalf("disabled option changed existing input handling: %v", err)
			}
		})
	}
	f := newPartitionSealFake(t)
	if err := executePartitionSealProof(context.Background(), f, 510, 3, time.Minute, true); err == nil || len(f.steps) != 0 {
		t.Fatal("ineligible coordinator bounds acquired resources")
	}
}

// TestProtectedSharedPartitionMappingNoTarget fails discovery after acquiring A.
// Enabled cleanup may schedule A, but the concrete adapter must issue no native
// scratch call without a validated dirty target. Region/VM/driver cleanup still
// runs; diagnostic discovery failure is not permission to guess a scratch GPA.
// Explicit bitmap 3 retains the original full-policy mapping scenario.
func TestProtectedSharedPartitionMappingNoTarget(t *testing.T) {
	f := newPartitionSealFake(t)
	f.failKind, f.failVM, f.failErr = "snapshot-after", "a", errors.New("discovery failed")
	err := executePartitionSealProof(context.Background(), f, 5, 3, time.Minute, true)
	if !errors.Is(err, f.failErr) ||
		partitionStepPosition(f.steps, "scratch-cleanup", "", "a") < 0 ||
		partitionStepPosition(f.steps, "scratch-cleanup", "", "b") >= 0 ||
		strings.Contains(strings.Join(f.events, ","), "native-unmap-") ||
		partitionStepPosition(f.steps, "remove", "primary", "a") < 0 ||
		partitionStepPosition(f.steps, "terminate", "", "a") < 0 ||
		partitionStepPosition(f.steps, "close-driver", "", "") < 0 {
		t.Fatal("failed discovery guessed scratch or suppressed actual owner cleanup")
	}
}

// TestProtectedSharedPartitionMappingSealFailure rejects failed/cancelled first
// and repeated seal submissions with probes enabled. No negative map phase or
// later forward work is authorized by an incomplete seal, and fresh independent
// cleanup must still remove both attempted ownership records.
// Explicit bitmap 3 preserves these full-policy failure expectations.
func TestProtectedSharedPartitionMappingSealFailure(t *testing.T) {
	for _, kind := range []string{"partition-seal", "partition-seal-repeat"} {
		for _, id := range []string{"a", "b"} {
			// A cancelled, failed operation must not authorize a phase change;
			// neither error says whether native irreversible work occurred.
			t.Run(kind+"/"+id, func(t *testing.T) {
				f := newPartitionSealFake(t)
				ctx, cancel := context.WithCancel(context.Background())
				defer cancel()
				f.failKind, f.failVM = kind, id
				f.failErr = errors.New("incomplete seal submission")
				f.cancel = cancel
				err := executePartitionSealProof(ctx, f, 5, 3, time.Minute, true)
				if !errors.Is(err, f.failErr) || !errors.Is(err, context.Canceled) {
					t.Fatal("failed seal boundary was accepted")
				}
				failed := partitionStepPosition(f.steps, kind, "", id)
				if failed < 0 {
					t.Fatal("failed seal was not submitted")
				}
				for _, s := range f.steps[failed+1:] {
					switch s.Kind {
					case "scratch-cleanup", "teardown", "remove", "terminate", "reclaim", "zero", "release", "close-driver":
					default:
						t.Errorf("incomplete seal authorized forward work: %s", s.Kind)
					}
				}
				if f.cleanupContextInvalid || f.doubleClose ||
					partitionStepPosition(f.steps, "terminate", "", "a") < 0 ||
					partitionStepPosition(f.steps, "terminate", "", "b") < 0 ||
					partitionStepPosition(f.steps, "close-driver", "", "") < 0 {
					t.Fatal("failed seal suppressed independent cleanup")
				}
			})
		}
	}
}

// partitionMappingStepNames serializes recorded step identity for exact-order
// assertions. Explicit phase/operation fields cannot be confused with page or
// lifetime identity. It reads fake diagnostics only and changes no ownership.
func partitionMappingStepNames(steps []partitionSealStep) []string {
	names := make([]string, 0, len(steps))
	for _, s := range steps {
		name := s.Kind + "/" + s.Lifetime + "/" + s.Participant
		if s.MappingPhase != "" || s.MappingOperation != 0 {
			name += fmt.Sprintf("/%s/%x", s.MappingPhase, uint16(s.MappingOperation))
		}
		names = append(names, name)
	}
	return names
}

// TestProtectedSharedPartitionMappingOrder checks the entire enabled serialized
// sequence, including both forms/unmaps, B's still-unsealed control and each
// participant's completed first/repeat seal boundary. Existing copy, fresh late,
// exchange and cleanup order must remain intact; no synthetic map enforces HV
// policy, and clean deferred scratch steps must do no native work.
// Explicit bitmap 3 retains the existing full-policy map sequence.
func TestProtectedSharedPartitionMappingOrder(t *testing.T) {
	f := newPartitionSealFake(t)
	if err := executePartitionSealProof(context.Background(), f, 5, 3, time.Minute, true); err != nil {
		t.Fatal(err)
	}
	expected := []string{
		"driver//", "open/primary/", "seed/primary/",
		"snapshot-before//a", "prepare/primary/a", "snapshot-after//a",
		"snapshot-before//b", "prepare/primary/b", "snapshot-after//b",
		"initialize/primary/", "initialize/primary/", "install/primary/a", "install/primary/b",
		"seal/primary/", "seal/primary/", "hv-positive/primary/a", "hv-positive/primary/b",
	}
	// Each explicit group requires contiguous then sparse, with a full unmap
	// between them. The expectation is independent of the coordinator's loop.
	addMaps := func(kind, id, phase string) {
		expected = append(expected, kind+"//"+id+"/"+phase+"/4b", "hv-unmap//"+id+"/"+phase+"/0",
			kind+"//"+id+"/"+phase+"/6e", "hv-unmap//"+id+"/"+phase+"/0")
	}
	addMaps("hv-map-positive", "a", "pre-seal")
	addMaps("hv-map-positive", "b", "pre-seal")
	expected = append(expected, "partition-seal/primary/a")
	addMaps("hv-map-negative", "a", "post-first-seal")
	addMaps("hv-map-positive", "b", "b-after-a-seal")
	expected = append(expected, "partition-seal/primary/b")
	addMaps("hv-map-negative", "b", "post-first-seal")
	expected = append(expected, "partition-seal-repeat/primary/a")
	addMaps("hv-map-negative", "a", "post-repeat-seal")
	expected = append(expected, "partition-seal-repeat/primary/b")
	addMaps("hv-map-negative", "b", "post-repeat-seal")
	expected = append(expected,
		"hv-negative/primary/a", "hv-negative/primary/b",
		"open/late/", "seed/late/", "late-prepare/late/a", "initialize/late/",
		"late-install-denial/late/a", "exchange/primary/",
		"scratch-cleanup//a/cleanup/0", "scratch-cleanup//b/cleanup/0",
		"teardown/primary/", "teardown/primary/", "remove/primary/a", "remove/primary/b",
		"teardown/late/", "remove/late/a", "terminate//a", "terminate//b",
		"reclaim/late/", "zero/late/", "release/late/",
		"reclaim/primary/", "reclaim/primary/", "zero/primary/", "release/primary/", "close-driver//")
	if got := strings.Join(partitionMappingStepNames(f.steps), "\n"); got != strings.Join(expected, "\n") {
		t.Fatalf("enabled order differs:\n%s", got)
	}
	for _, id := range []string{"a", "b"} {
		if f.discovery.scratch[id].dirty {
			t.Error("accepted outcomes left dirty scratch")
		}
	}
	if strings.Count(strings.Join(f.events, ","), "native-unmap-") != 14 ||
		f.cleanupContextInvalid || f.doubleClose {
		t.Fatal("accepted maps lacked whole-range unmap or clean deferred cleanup did native work")
	}
}

// TestProtectedSharedPartitionMappingFailures injects focused errors/cancellation
// and sticky evidence failure at each new boundary. Forward dispatch must stop,
// while the real dirty-ledger unmap runs under fresh cleanup before teardown;
// even a scratch cleanup error must not suppress existing cleanup/driver close.
// The fake records attempts only, never simulating native seal enforcement.
// Explicit bitmap 3 preserves these existing full-policy failure scenarios.
func TestProtectedSharedPartitionMappingFailures(t *testing.T) {
	for _, scenario := range []struct {
		name, kind, id, phase, failure string
		operation                     protectedSharedHvMappingOperation
		cleanupFailure                bool
	}{
		{"pre A error", "hv-map-positive", "a", "pre-seal", "error", protectedSharedHvMapContiguous, false},
		{"pre B cancel", "hv-map-positive", "b", "pre-seal", "cancel", protectedSharedHvMapSparse, false},
		{"A first evidence", "hv-map-negative", "a", "post-first-seal", "evidence", protectedSharedHvMapContiguous, false},
		{"B control error", "hv-map-positive", "b", "b-after-a-seal", "error", protectedSharedHvMapSparse, false},
		{"B first cancel", "hv-map-negative", "b", "post-first-seal", "cancel", protectedSharedHvMapContiguous, false},
		{"A repeat error", "hv-map-negative", "a", "post-repeat-seal", "error", protectedSharedHvMapSparse, false},
		{"B repeat error", "hv-map-negative", "b", "post-repeat-seal", "error", protectedSharedHvMapContiguous, false},
		{"normal unmap failure", "hv-unmap", "a", "pre-seal", "error", 0, false},
		{"cleanup also fails", "hv-map-positive", "a", "pre-seal", "error", protectedSharedHvMapContiguous, true},
	} {
		// Each isolated run has fresh synthetic owners and a separate forward
		// context, so cancellation cannot be hidden by another successful run.
		t.Run(scenario.name, func(t *testing.T) {
			f := newPartitionSealFake(t)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			f.failKind, f.failVM, f.failPhase = scenario.kind, scenario.id, scenario.phase
			f.failOperation = scenario.operation
			switch scenario.failure {
			case "error":
				f.failErr = errors.New("mapping step failed")
			case "cancel":
				f.cancel = cancel
			case "evidence":
				f.evidenceOnFailure = true
			}
			if scenario.cleanupFailure {
				f.scratchCleanupErr = errors.New("independent unmap failed")
			}
			err := executePartitionSealProof(ctx, f, 5, 3, time.Minute, true)
			if err == nil || (f.failErr != nil && !errors.Is(err, f.failErr)) ||
				(scenario.failure == "cancel" && !errors.Is(err, context.Canceled)) ||
				(scenario.failure == "evidence" && !errors.Is(err, f.evidenceErr)) ||
				(scenario.cleanupFailure && !errors.Is(err, f.scratchCleanupErr)) {
				t.Fatal("mapping/cleanup failure was not retained")
			}
			failed := -1
			for i, s := range f.steps {
				if s.Kind == scenario.kind && s.Participant == scenario.id &&
					s.MappingPhase == scenario.phase && s.MappingOperation == scenario.operation {
					failed = i
					break
				}
			}
			if failed < 0 {
				t.Fatal("configured mapping boundary was skipped")
			}
			for _, s := range f.steps[failed+1:] {
				switch s.Kind {
				case "scratch-cleanup", "teardown", "remove", "terminate", "reclaim", "zero", "release", "close-driver":
				default:
					t.Errorf("forward work continued after mapping failure: %s", s.Kind)
				}
			}
			cleanup := partitionStepPosition(f.steps, "scratch-cleanup", "", scenario.id)
			teardown := partitionStepPosition(f.steps, "teardown", "primary", "")
			if cleanup <= failed || teardown <= cleanup ||
				f.discovery.scratch[scenario.id].dirty != scenario.cleanupFailure {
				t.Fatal("concrete scratch cleanup did not precede teardown or lost dirty failure state")
			}
			// A real unmap invocation must precede the synthetic native region
			// cleanup event, not merely appear as a scheduled no-op step.
			events := strings.Join(f.events, ",")
			unmap := strings.LastIndex(events, "native-unmap-"+scenario.id)
			if unmap < 0 || unmap > strings.Index(events, "native-teardown-primary") {
				t.Fatal("dirty cleanup did not issue native unmap before region teardown")
			}
			for _, id := range []string{"a", "b"} {
				if partitionStepPosition(f.steps, "remove", "primary", id) < 0 ||
					partitionStepPosition(f.steps, "terminate", "", id) < 0 {
					t.Error("mapping failure suppressed existing owned VM cleanup")
				}
			}
			if partitionStepPosition(f.steps, "release", "primary", "") < 0 ||
				partitionStepPosition(f.steps, "close-driver", "", "") < 0 ||
				f.cleanupContextInvalid || f.doubleClose {
				t.Fatal("mapping failure suppressed existing cleanup or inherited cancellation")
			}
		})
	}
}

// TestProtectedSharedPartitionMappingLedger exercises the concrete pre-dispatch
// dirty transition and metadata-only evidence using the existing IOCTL seam.
// Transport failure/cancellation/failed evidence must preserve dirty state until
// independent whole-range cleanup. Synthetic responses are not HV-policy proof;
// U2 separately owns wire/progress classification.
func TestProtectedSharedPartitionMappingLedger(t *testing.T) {
	for _, failure := range []string{"transport", "cancellation", "evidence"} {
		// The synthetic validated ledger owns no real VM or backing. Only the
		// actual adapter's state transition and evidence writer are exercised.
		t.Run(failure, func(t *testing.T) {
			f := newPartitionSealFake(t)
			p := f.discovery
			p.primary.evidence.writer = f
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			s := &partitionSealScratch{
				target: protectedSharedHvTarget{partitionID: 42, partitionIDValid: true, pageGPA: 105 * 4096},
				pages: [3]uint64{105, 106, 107}, vmID: "synthetic-a", runtime: "synthetic-runtime",
			}
			p.scratch = map[string]*partitionSealScratch{"a": s}
			transportErr := errors.New("synthetic transport failed")
			writeErr := errors.New("synthetic evidence writer failed")
			// This synchronous seam checks dirty publication before supplying
			// synthetic progress, cancellation or diagnostic-writer failure.
			p.probe = &protectedSharedHvProbe{handle: 123,
				ioctl: func(_ windows.Handle, _ uint32, input, output []byte) (uint32, error) {
					if !s.dirty {
						t.Fatal("native mapping dispatched before dirty publication")
					}
					if binary.LittleEndian.Uint16(input[8:10]) == uint16(protectedSharedHvUnmapScratch) {
						binary.LittleEndian.PutUint32(output[4:8], 3)
						return 4096, nil
					}
					switch failure {
					case "transport":
						return 4096, transportErr
					case "cancellation":
						cancel()
					case "evidence":
						f.evidenceWriteErr = writeErr
					}
					binary.LittleEndian.PutUint32(output[4:8], 2)
					return 4096, nil
				}}
			err := p.mappingAttempt(ctx, "a", "pre-seal", s, protectedSharedHvMapContiguous, false)
			if err == nil || !s.dirty ||
				(failure == "transport" && !errors.Is(err, transportErr)) ||
				(failure == "cancellation" && !errors.Is(err, context.Canceled)) ||
				(failure == "evidence" && !errors.Is(err, writeErr)) {
				t.Fatal("mapping failure hid dirty state or lost its error")
			}
			// Restore the sink, not its sticky owner error. Cleanup must still
			// dispatch and clear valid progress while returning evidence failure.
			f.evidenceWriteErr = nil
			cleanupCtx, stop := context.WithTimeout(context.WithoutCancel(ctx), time.Minute)
			defer stop()
			cleanupErr := p.cleanupScratch(cleanupCtx, "a", "cleanup")
			if s.dirty || (failure == "evidence") != errors.Is(cleanupErr, writeErr) ||
				(failure != "evidence" && cleanupErr != nil) {
				t.Fatal("independent cleanup was suppressed or evidence failure was not sticky")
			}
			for _, line := range strings.Split(strings.TrimSpace(f.evidenceBuffer.String()), "\n") {
				var record struct {
					Kind string
					Data map[string]json.RawMessage
				}
				if err := json.Unmarshal([]byte(strings.TrimPrefix(line, "PROTECTED-EVIDENCE ")), &record); err != nil {
					t.Fatal(err)
				}
				if record.Kind != "hv-map" {
					t.Fatal("mapping attempt lacked its evidence kind")
				}
				for _, field := range []string{"Participant", "ID", "Runtime", "HypervisorPartitionId", "Operation",
					"OperationCode", "Phase", "Flags", "DestinationPageIndices", "RequestedCount", "ExpectedProcessed", "ExpectedRawStatus",
					"TransportError", "ReturnedBytes", "FramingValid", "RawStatusValid", "RawStatus", "ElementsProcessed",
					"ProtocolError", "ValidationError", "ContextError"} {
					if _, present := record.Data[field]; !present {
						t.Errorf("mapping evidence omitted %s", field)
					}
				}
				for _, forbidden := range []string{"Data", "Bytes", "Readback", "DataValid"} {
					if _, present := record.Data[forbidden]; present {
						t.Error("mapping evidence exported memory/readback claims")
					}
				}
			}
		})
	}
}
