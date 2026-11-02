//go:build windows

// Copyright (c) Microsoft Corporation. All rights reserved.

package main

import (
	"bytes"
	"encoding/binary"
	"errors"
	"math"
	"runtime"
	"testing"
	"unsafe"

	"golang.org/x/sys/windows"
)

// TestProtectedSharedHvScratchPages checks section sizes and reservation address
// boundaries without allocating or mapping memory. Only three pages wholly in
// rounded padding may be returned; invalid inputs yield no usable pages, guarding
// primary/late mappings and the reservation's full representable byte range.
func TestProtectedSharedHvScratchPages(t *testing.T) {
	const lastPage = uint64(math.MaxUint64 / 4096)
	for _, scenario := range []struct {
		name    string
		primary uint64
		pages   uint64
		valid   bool
	}{
		{"one", 0x1000, 1, true},
		{"default five", 0x1000, 5, true},
		{"exact padding", 0x1000, 509, true},
		{"new reservation block", 0x1000, 513, true},
		{"maximum padded count", 0x1000, 4093, true},
		{"two padding pages", 0x1000, 510, false},
		{"one padding page", 0x1000, 511, false},
		{"no padding pages", 0x1000, 512, false},
		{"maximum no padding", 0x1000, 4096, false},
		{"zero count", 0x1000, 0, false},
		{"too many pages", 0x1000, 4097, false},
		{"count overflow", 0x1000, math.MaxUint64, false},
		{"last representable reservation", lastPage - 511, 1, true},
		{"reservation byte overflow", lastPage - 510, 1, false},
		{"scratch byte overflow", lastPage, 5, false},
		{"page addition overflow", math.MaxUint64 - 4, 5, false},
	} {
		got, err := protectedSharedHvScratchPages(scenario.primary, scenario.pages)
		if (err == nil) != scenario.valid {
			t.Errorf("%s: pages=%v error=%v", scenario.name, got, err)
			continue
		}
		if !scenario.valid {
			if got != [3]uint64{} {
				t.Errorf("%s: failure published scratch pages", scenario.name)
			}
			continue
		}
		want := [3]uint64{
			scenario.primary + scenario.pages,
			scenario.primary + scenario.pages + 1,
			scenario.primary + scenario.pages + 2,
		}
		reserved := (scenario.pages + 511) &^ uint64(511)
		if got != want || got[0] < scenario.primary+scenario.pages || got[2] >= scenario.primary+reserved {
			t.Errorf("%s: scratch=%v want=%v within reservation", scenario.name, got, want)
		}
	}
}

// TestProtectedSharedHvMappingGolden compares independent literal native headers
// and payloads against every byte of the fixed input, protecting offsets, flags,
// counts, the sparse hole and all zero source/padding bytes. No native work is
// done; byte GPAs must become page indices exactly once.
func TestProtectedSharedHvMappingGolden(t *testing.T) {
	target := protectedSharedHvTarget{
		partitionID: 0x0102030405060708, partitionIDValid: true, pageGPA: 0x1020304050607000,
	}
	for _, scenario := range []struct {
		operation protectedSharedHvMappingOperation
		header    string
		payload   string
		count     uint32
	}{
		{
			protectedSharedHvMapContiguous,
			"04000000020000004b00000028000000000000000200000000000000",
			"0807060504030201" + "0706050403020100" +
				"0d00020000000000" + "0000000000000000" + "0000000000000000",
			2,
		},
		{
			protectedSharedHvMapSparse,
			"04000000020000006e00000030000000000000000200000000000000",
			"0807060504030201" + "0d00020000000000" +
				"0706050403020100" + "0000000000000000" +
				"0906050403020100" + "0000000000000000",
			2,
		},
		{
			protectedSharedHvUnmapScratch,
			"04000000020000004c00000018000000000000000300000000000000",
			"0807060504030201" + "0706050403020100" + "0000000000000000",
			3,
		},
	} {
		frame, count, err := encodeProtectedSharedHvMappingRequest(target, scenario.operation)
		if err != nil {
			t.Fatal(err)
		}
		want := make([]byte, 8192)
		copy(want, protectedSharedHvGolden(t, scenario.header))
		copy(want[4096:], protectedSharedHvGolden(t, scenario.payload))
		if count != scenario.count || !bytes.Equal(frame, want) {
			t.Errorf("operation=%#x: utility wire differs from golden", scenario.operation)
		}
	}
	if protectedSharedHvMappingIOCTLCode != 5 || protectedSharedHvMappingFlags != 0x2000d || protectedSharedHvMappingDenied != 8 {
		t.Fatal("matched utility IOCTL, ZERO read-execute flags or raw denial changed")
	}
}

// TestProtectedSharedHvMappingBounds rejects uncorrelated/invalid/SELF targets,
// byte misalignment, three-page overflow and unsupported operations before the
// synchronous fake is called. The last full three-page interval remains valid;
// validation errors must not be mistaken for native admission evidence.
func TestProtectedSharedHvMappingBounds(t *testing.T) {
	for _, scenario := range []string{"valid", "last three pages", "uncorrelated", "invalid ID", "SELF", "unaligned", "scratch overflow", "address overflow", "unsupported operation"} {
		target := protectedSharedHvTarget{partitionID: 42, partitionIDValid: true, pageGPA: 0x1000}
		operation := protectedSharedHvMapContiguous
		switch scenario {
		case "last three pages":
			target.pageGPA = math.MaxUint64 - (3*4096 - 1)
		case "uncorrelated":
			target.partitionIDValid = false
		case "invalid ID":
			target.partitionID = 0
		case "SELF":
			target.partitionID = math.MaxUint64
		case "unaligned":
			target.pageGPA++
		case "scratch overflow":
			target.pageGPA = math.MaxUint64 - (2*4096 - 1)
		case "address overflow":
			target.pageGPA = math.MaxUint64
		case "unsupported operation":
			operation = 0x42
		}
		valid := scenario == "valid" || scenario == "last three pages"
		frame, count, err := encodeProtectedSharedHvMappingRequest(target, operation)
		if (err == nil) != valid || (!valid && (frame != nil || count != 0)) {
			t.Errorf("%s: invalid encoder bounds acceptance", scenario)
		}
		if valid {
			continue
		}
		calls := 0
		// The synchronous fake records any forbidden dispatch and retains no
		// borrowed buffers or handle; invalid requests must never reach it.
		probe := &protectedSharedHvProbe{handle: windows.Handle(1), ioctl: func(windows.Handle, uint32, []byte, []byte) (uint32, error) {
			calls++
			return 4096, nil
		}}
		result := probe.mapping(target, operation)
		if calls != 0 || result.rawStatusValid || result.requireMapPositive() == nil || result.requireMapDenial() == nil {
			t.Errorf("%s: invalid target reached transport or qualified", scenario)
		}
	}
}

// TestProtectedSharedHvMappingResults exercises raw output and exact framing,
// including superficially successful bytes on failed transport and a converted
// copy denial truncated into the raw field. Only exact two-element map success,
// raw 8/zero map denial, or three-element unmap success can qualify; partial,
// impossible or unrelated results cannot manufacture a passing policy check.
func TestProtectedSharedHvMappingResults(t *testing.T) {
	transportErr := errors.New("synthetic transport failure")
	for _, scenario := range []struct {
		name        string
		wire        string
		count       uint32
		bufferSize  int
		returned    uint32
		transport   error
		framed      bool
		protocolErr bool
		mapPositive bool
		mapDenial   bool
		unmap       bool
	}{
		{"map success", "0000000002000000", 2, 4096, 4096, nil, true, false, true, false, false},
		{"map denial", "0800000000000000", 2, 4096, 4096, nil, true, false, false, true, false},
		{"unmap success", "0000000003000000", 3, 4096, 4096, nil, true, false, false, false, true},
		{"unrelated status", "0200000000000000", 2, 4096, 4096, nil, true, false, false, false, false},
		{"unsupported call", "0100000000000000", 2, 4096, 4096, nil, true, false, false, false, false},
		{"truncated copy denial", "060035c000000000", 2, 4096, 4096, nil, true, false, false, false, false},
		{"denial with progress", "0800000001000000", 2, 4096, 4096, nil, true, false, false, false, false},
		{"incomplete map", "0000000001000000", 2, 4096, 4096, nil, true, false, false, false, false},
		{"zero progress success", "0000000000000000", 2, 4096, 4096, nil, true, false, false, false, false},
		{"incomplete unmap", "0000000002000000", 3, 4096, 4096, nil, true, false, false, false, false},
		{"unmap denial is not map denial", "0800000000000000", 3, 4096, 4096, nil, true, false, false, false, false},
		{"impossible map progress", "0000000003000000", 2, 4096, 4096, nil, true, true, false, false, false},
		{"impossible unmap progress", "0000000004000000", 3, 4096, 4096, nil, true, true, false, false, false},
		{"huge progress", "08000000ffffffff", 2, 4096, 4096, nil, true, true, false, false, false},
		{"short return", "0000000002000000", 2, 4096, 8, nil, false, true, false, false, false},
		{"zero return", "0800000000000000", 2, 4096, 0, nil, false, true, false, false, false},
		{"oversized return", "0800000000000000", 2, 4096, 4097, nil, false, true, false, false, false},
		{"short buffer", "0800000000000000", 2, 8, 4096, nil, false, true, false, false, false},
		{"oversized buffer", "0000000002000000", 2, 4097, 4096, nil, false, true, false, false, false},
		{"invalid request count", "0000000002000000", 0, 4096, 4096, nil, false, true, false, false, false},
		{"failed transport plausible success", "0000000002000000", 2, 4096, 4096, transportErr, false, false, false, false, false},
		{"failed transport plausible denial", "0800000000000000", 2, 4096, 4096, transportErr, false, false, false, false, false},
	} {
		output := make([]byte, scenario.bufferSize)
		copy(output, protectedSharedHvGolden(t, scenario.wire))
		result := decodeProtectedSharedHvMappingResult(output, scenario.returned, scenario.count, scenario.transport)
		if result.framingValid != scenario.framed || result.rawStatusValid != scenario.framed ||
			(result.protocolError != nil) != scenario.protocolErr || result.returnedBytes != scenario.returned ||
			(result.requireMapPositive() == nil) != scenario.mapPositive ||
			(result.requireMapDenial() == nil) != scenario.mapDenial ||
			(result.requireUnmapPositive() == nil) != scenario.unmap {
			t.Errorf("%s: incorrect result validity/classification: %+v", scenario.name, result)
		}
		if scenario.transport != nil && (!errors.Is(result.transportError, transportErr) ||
			result.rawStatus != 0 || result.elementsProcessed != 0) {
			t.Errorf("%s: transport failure interpreted output or lost error", scenario.name)
		}
		if scenario.framed && (result.rawStatus != binary.LittleEndian.Uint16(output[0:2]) ||
			result.elementsProcessed != binary.LittleEndian.Uint32(output[4:8])) {
			t.Errorf("%s: raw diagnostics were not retained", scenario.name)
		}
	}
	if (protectedSharedHvMappingResult{}).requireMapPositive() == nil ||
		(protectedSharedHvMappingResult{}).requireMapDenial() == nil ||
		(protectedSharedHvMappingResult{}).requireUnmapPositive() == nil {
		t.Fatal("uninitialized result qualified")
	}
}

// TestProtectedSharedHvMappingTransport checks the real dispatch boundary with
// a synchronous fake: both page-aligned buffers, fixed sizes, page-offset payload,
// complete encoded contents and initially zero output must survive GC inside the
// call. It also ensures transport errors carrying plausible output stay invalid
// and unsupported architecture cannot dispatch. No driver or VM is accessed.
func TestProtectedSharedHvMappingTransport(t *testing.T) {
	target := protectedSharedHvTarget{partitionID: 42, partitionIDValid: true, pageGPA: 0x12345000}
	transportErr := errors.New("fake IOCTL failed after writing output")
	for _, operation := range []protectedSharedHvMappingOperation{protectedSharedHvMapContiguous, protectedSharedHvMapSparse, protectedSharedHvUnmapScratch} {
		for _, failTransport := range []bool{false, true} {
			frame, count, err := encodeProtectedSharedHvMappingRequest(target, operation)
			if err != nil {
				t.Fatal(err)
			}
			calls := 0
			// The fake borrows buffers synchronously, inspects them after GC,
			// and publishes only a synthetic control header; it retains nothing.
			probe := &protectedSharedHvProbe{handle: windows.Handle(7), ioctl: func(handle windows.Handle, code uint32, input, output []byte) (uint32, error) {
				calls++
				runtime.GC()
				if handle != windows.Handle(7) || code != 5 || len(input) != 8192 || len(output) != 4096 ||
					uintptr(unsafe.Pointer(&input[0]))%4096 != 0 || uintptr(unsafe.Pointer(&output[0]))%4096 != 0 {
					t.Fatal("utility dispatch lost fixed framing, handle or alignment")
				}
				if !bytes.Equal(input, frame) || !bytes.Equal(output, make([]byte, 4096)) ||
					binary.LittleEndian.Uint64(input[4096:4104]) != target.partitionID {
					t.Fatal("utility dispatch changed encoded input or supplied nonzero output")
				}
				binary.LittleEndian.PutUint32(output[4:8], count)
				if failTransport {
					return 4096, transportErr
				}
				return 4096, nil
			}}
			result := probe.mapping(target, operation)
			if runtime.GOARCH != "amd64" {
				if calls != 0 || result.transportError == nil || result.rawStatusValid {
					t.Fatal("unsupported architecture reached utility transport")
				}
				continue
			}
			if calls != 1 {
				t.Fatal("bounded operation did not dispatch exactly once")
			}
			if failTransport {
				if !errors.Is(result.transportError, transportErr) || result.rawStatusValid ||
					result.elementsProcessed != 0 || result.requireMapPositive() == nil || result.requireUnmapPositive() == nil {
					t.Fatal("failed transport's plausible output became usable")
				}
				continue
			}
			if operation == protectedSharedHvUnmapScratch {
				err = result.requireUnmapPositive()
			} else {
				err = result.requireMapPositive()
			}
			if err != nil {
				t.Fatal(err)
			}
		}
	}
}

// TestProtectedSharedHvMappingPrerequisites requires unavailable handles/seams
// and unsupported aligned-storage sizes to fail without dispatch or usable
// output. This protects the shared driver's ownership boundary and bounds all
// allocations to the two established utility sizes.
func TestProtectedSharedHvMappingPrerequisites(t *testing.T) {
	calls := 0
	// This fake only detects forbidden dispatch from a closed/invalid client;
	// it borrows nothing beyond the synchronous call.
	ioctl := func(windows.Handle, uint32, []byte, []byte) (uint32, error) {
		calls++
		return 4096, nil
	}
	for _, probe := range []*protectedSharedHvProbe{
		nil,
		{handle: 0, ioctl: ioctl},
		{handle: windows.InvalidHandle, ioctl: ioctl},
		{handle: windows.Handle(1)},
	} {
		result := probe.mapping(protectedSharedHvTarget{partitionID: 42, partitionIDValid: true, pageGPA: 4096}, protectedSharedHvMapContiguous)
		if result.transportError == nil || result.rawStatusValid || calls != 0 {
			t.Fatal("unavailable client reached transport or published raw output")
		}
	}
	for _, size := range []int{-1, 0, 8, 4095, 4097, 8193} {
		storage, view, err := protectedSharedHvMappingAligned(size)
		if err == nil || storage != nil || view != nil {
			t.Errorf("unsupported buffer size=%d accepted", size)
		}
	}
}
