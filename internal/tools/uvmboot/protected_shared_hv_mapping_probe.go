//go:build windows

// Copyright (c) Microsoft Corporation. All rights reserved.

package main

import (
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"runtime"
	"unsafe"

	"golang.org/x/sys/windows"
)

// The matched native utility ABI is in onecore/hv/test/common/tf/inc/
// tfkcontrol.h:51-139,454-471 and tfk/tfkutil.c:1516-1565. The native client
// tf/util/tfutil.cpp:240-365 uses page-aligned storage and a page-offset payload.
// Payload offsets follow hvx/hc/hcam.c:393-407 and published/hvhdk_mini.w:
// 5470-5540. These utility frames are distinct from the legacy testcase frames.
const (
	protectedSharedHvMappingIOCTLCode uint32 = (1 << 2) | 1
	protectedSharedHvMappingPageSize        = 4096
	protectedSharedHvMappingInputSize       = 8192
	protectedSharedHvMappingFlags     uint32 = 0x0002000d
	protectedSharedHvMappingDenied    uint16 = 8
)

// protectedSharedHvMappingOperation selects only the two bounded ZERO map
// forms and whole-scratch unmap; it is not an arbitrary hypercall interface.
type protectedSharedHvMappingOperation uint16

const (
	protectedSharedHvMapContiguous protectedSharedHvMappingOperation = 0x004b
	protectedSharedHvMapSparse     protectedSharedHvMappingOperation = 0x006e
	protectedSharedHvUnmapScratch  protectedSharedHvMappingOperation = 0x004c
)

// protectedSharedHvMappingResult owns diagnostics only, never returned memory.
// Transport failure leaves output uninterpreted. framingValid means an exact
// output page was received; rawStatusValid then permits raw status/progress
// diagnostics, even if impossible progress sets protocolError. Only the exact
// validators below acknowledge an outcome. Raw 16-bit HV_STATUS is not converted
// WinHv NTSTATUS (including the copy probe's 0xc0350006) or HRESULT.
type protectedSharedHvMappingResult struct {
	transportError    error
	returnedBytes     uint32
	protocolError     error
	framingValid      bool
	rawStatusValid    bool
	rawStatus         uint16
	requestedCount    uint32
	elementsProcessed uint32
}

// protectedSharedHvScratchPages derives three consecutive scratch page indices
// after sectionPages actual pages at primaryPage, within its 512-page-rounded
// reservation. It is pure and returns no usable pages on invalid count, fewer
// than three padding pages, addition overflow or an unrepresentable reservation
// byte range. Inputs/outputs are page indices, not byte GPAs; it neither reserves
// memory nor proves the caller's ownership of the supplied primary interval.
func protectedSharedHvScratchPages(primaryPage, sectionPages uint64) ([3]uint64, error) {
	if sectionPages == 0 || sectionPages > 4096 {
		return [3]uint64{}, errors.New("hvtest scratch requires 1..4096 section pages")
	}
	reservedPages := (sectionPages + 511) &^ uint64(511)
	if reservedPages-sectionPages < 3 {
		return [3]uint64{}, errors.New("hvtest scratch requires three allocator padding pages")
	}
	// Validate the full reservation, not just the three scratch pages. The
	// inclusive final byte may be MaxUint64; an exclusive byte end need not fit.
	if primaryPage > math.MaxUint64-reservedPages ||
		primaryPage+reservedPages-1 > math.MaxUint64/protectedSharedHvMappingPageSize {
		return [3]uint64{}, errors.New("hvtest scratch reservation address overflows")
	}
	first := primaryPage + sectionPages
	return [3]uint64{first, first + 1, first + 2}, nil
}

// protectedSharedHvMappingAligned returns zeroed owned storage and a page-aligned
// view for only the fixed input/output sizes. Invalid sizes yield no buffers.
// Both storage and view must remain alive through synchronous real/fake IOCTL;
// this allocates ordinary bytes, not physical backing or native mappings.
func protectedSharedHvMappingAligned(size int) (storage, view []byte, err error) {
	if size != protectedSharedHvMappingInputSize && size != protectedSharedHvMappingPageSize {
		return nil, nil, errors.New("hvtest mapping buffer requires a fixed utility size")
	}
	storage = make([]byte, size+protectedSharedHvMappingPageSize-1)
	offset := int((protectedSharedHvMappingPageSize - uintptr(unsafe.Pointer(&storage[0]))%protectedSharedHvMappingPageSize) % protectedSharedHvMappingPageSize)
	return storage, storage[offset : offset+size], nil
}

// encodeProtectedSharedHvMappingRequest returns an owned zero-padded utility
// frame and requested rep count, or no usable frame on invalid operation/target.
// target.pageGPA is the byte-aligned first scratch page, explicitly converted
// once to a native page index. All three full pages must fit. Correlation is
// required but is not ownership authority; callers supply a live owned scratch
// interval. Source placeholders stay zero because the fixed ZERO special form
// ignores them, not because ordinary physical frame zero is backing.
func encodeProtectedSharedHvMappingRequest(target protectedSharedHvTarget, operation protectedSharedHvMappingOperation) ([]byte, uint32, error) {
	if !target.partitionIDValid || target.partitionID == 0 || target.partitionID == math.MaxUint64 ||
		target.pageGPA%protectedSharedHvMappingPageSize != 0 ||
		target.pageGPA > math.MaxUint64-(3*protectedSharedHvMappingPageSize-1) {
		return nil, 0, errors.New("hvtest mapping requires a correlated non-SELF target and three full aligned scratch pages")
	}
	var payloadSize, count uint32
	switch operation {
	case protectedSharedHvMapContiguous:
		payloadSize, count = 40, 2
	case protectedSharedHvMapSparse:
		payloadSize, count = 48, 2
	case protectedSharedHvUnmapScratch:
		payloadSize, count = 24, 3
	default:
		return nil, 0, errors.New("hvtest mapping operation is not a bounded scratch operation")
	}
	frame := make([]byte, protectedSharedHvMappingInputSize)
	binary.LittleEndian.PutUint32(frame[0:4], 4) // TFK_OID_HV_HYPERCALL
	binary.LittleEndian.PutUint32(frame[4:8], 2) // TFK_OBJ_METHOD
	binary.LittleEndian.PutUint16(frame[8:10], uint16(operation))
	binary.LittleEndian.PutUint32(frame[12:16], payloadSize)
	binary.LittleEndian.PutUint32(frame[20:24], count)
	// OutputSize and VariableHeaderSize remain zero: only the utility control
	// output is returned, and this interface has no explicit rep-start field.
	payload := frame[protectedSharedHvMappingPageSize:]
	page := target.pageGPA / protectedSharedHvMappingPageSize
	binary.LittleEndian.PutUint64(payload[0:8], target.partitionID)
	switch operation {
	case protectedSharedHvMapContiguous:
		binary.LittleEndian.PutUint64(payload[8:16], page)
		binary.LittleEndian.PutUint32(payload[16:20], protectedSharedHvMappingFlags)
	case protectedSharedHvMapSparse:
		binary.LittleEndian.PutUint32(payload[8:12], protectedSharedHvMappingFlags)
		binary.LittleEndian.PutUint64(payload[16:24], page)
		binary.LittleEndian.PutUint64(payload[32:40], page+2)
	case protectedSharedHvUnmapScratch:
		binary.LittleEndian.PutUint64(payload[8:16], page)
	}
	return frame, count, nil
}

// decodeProtectedSharedHvMappingResult borrows output only after successful
// transport and requires the entire supplied output page, not the eight-byte
// header. count must be the bounded request's two or three elements. Malformed
// sizes/counts and impossible progress are protocol failures, never policy
// evidence. It retains no slice and does not interpret any hypercall data.
func decodeProtectedSharedHvMappingResult(output []byte, returned, count uint32, transportErr error) protectedSharedHvMappingResult {
	r := protectedSharedHvMappingResult{transportError: transportErr, returnedBytes: returned, requestedCount: count}
	if transportErr != nil {
		return r
	}
	if len(output) != protectedSharedHvMappingPageSize || returned != protectedSharedHvMappingPageSize ||
		(count != 2 && count != 3) {
		r.protocolError = fmt.Errorf("hvtest mapping protocol mismatch: buffer=%d returned=%d requested=%d", len(output), returned, count)
		return r
	}
	r.framingValid = true
	r.rawStatusValid = true
	r.rawStatus = binary.LittleEndian.Uint16(output[0:2])
	r.elementsProcessed = binary.LittleEndian.Uint32(output[4:8])
	if r.elementsProcessed > count {
		r.protocolError = fmt.Errorf("hvtest mapping progress=%d exceeds requested=%d", r.elementsProcessed, count)
	}
	return r
}

// mapping synchronously dispatches only a bounded ZERO map or whole-scratch
// unmap on the existing owned handle. Callers serialize it against enumeration,
// copies and Close, retaining the target VM and scratch reservation throughout.
// Unsupported architecture/closed driver or invalid requests do no transport.
// Real and fake IOCTL borrow page-aligned owned buffers until return; neither
// cancellation nor a failed response proves that native state was unchanged.
func (p *protectedSharedHvProbe) mapping(target protectedSharedHvTarget, operation protectedSharedHvMappingOperation) protectedSharedHvMappingResult {
	if runtime.GOARCH != "amd64" || p == nil || p.handle == 0 || p.handle == windows.InvalidHandle || p.ioctl == nil {
		return protectedSharedHvMappingResult{transportError: errors.New("hvtest mapping prerequisite: unavailable AMD64 driver client")}
	}
	frame, count, err := encodeProtectedSharedHvMappingRequest(target, operation)
	if err != nil {
		return protectedSharedHvMappingResult{protocolError: err}
	}
	inputStorage, input, err := protectedSharedHvMappingAligned(protectedSharedHvMappingInputSize)
	if err != nil {
		return protectedSharedHvMappingResult{protocolError: err}
	}
	copy(input, frame)
	outputStorage, output, err := protectedSharedHvMappingAligned(protectedSharedHvMappingPageSize)
	if err != nil {
		return protectedSharedHvMappingResult{protocolError: err}
	}
	returned, ioctlErr := p.ioctl(p.handle, protectedSharedHvMappingIOCTLCode, input, output)
	runtime.KeepAlive(inputStorage)
	runtime.KeepAlive(outputStorage)
	return decodeProtectedSharedHvMappingResult(output, returned, count, ioctlErr)
}

// requireExact accepts only valid transport/framing/progress and the supplied
// exact raw status, requested count and processed count. It has no native effects;
// incomplete success, unrelated failures and impossible progress remain errors.
func (r protectedSharedHvMappingResult) requireExact(status uint16, requested, processed uint32) error {
	if r.transportError != nil {
		return r.transportError
	}
	if r.protocolError != nil {
		return r.protocolError
	}
	if !r.framingValid || !r.rawStatusValid || r.rawStatus != status ||
		r.requestedCount != requested || r.elementsProcessed != processed {
		return fmt.Errorf("hvtest mapping outcome mismatch: framing=%t raw-valid=%t status=%#04x requested=%d processed=%d; expected status=%#04x requested=%d processed=%d",
			r.framingValid, r.rawStatusValid, r.rawStatus, r.requestedCount, r.elementsProcessed, status, requested, processed)
	}
	return nil
}

// requireMapPositive requires exact raw success and both map elements processed.
// It acknowledges admission only, not byte readback or independently measured
// mapping effects; the caller must still unmap the whole scratch interval.
func (r protectedSharedHvMappingResult) requireMapPositive() error {
	return r.requireExact(0, 2, 2)
}

// requireMapDenial requires only raw OPERATION_DENIED (8) with zero progress on
// valid transport/framing. Converted copy denial, ACL failures and partial
// progress cannot qualify; cleanup remains necessary even for accepted denial.
func (r protectedSharedHvMappingResult) requireMapDenial() error {
	return r.requireExact(protectedSharedHvMappingDenied, 2, 0)
}

// requireUnmapPositive requires exact raw success and all three scratch pages
// processed, including already absent pages. Only this acknowledgement permits
// the caller to clear its conservative scratch-dirty ledger.
func (r protectedSharedHvMappingResult) requireUnmapPositive() error {
	return r.requireExact(0, 3, 3)
}
