//go:build windows

// Copyright (c) Microsoft Corporation. All rights reserved.

package main

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"math"
	"runtime"
	"testing"
	"unsafe"

	"golang.org/x/sys/windows"
)

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
