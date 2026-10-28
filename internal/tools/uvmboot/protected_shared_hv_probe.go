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

// These are the unchanged matched os.2020 AMD64 test-driver contracts, inspected
// after native S3 e6773b8e16f49b35b04a75003ee94d7830299e45:
//   - test/common/tf/inc/tfkcontrol.h: type 0, function 2, METHOD_IN_DIRECT (1),
//     FILE_ANY_ACCESS (0); TFK_TESTCASE_HEADER is size/alignment 16, NOT 4.
//   - test/common/tf/inc/tfcomponent.h and hvtest/inc/hvtestcasedefs.h:
//     component 101, ReadGpa 35, WriteGpa 36.
//   - test/nt/winhv/inc/winhvkt.h: native (not packed) AMD64 input offsets
//     PartitionId 0, VpIndex 8, BaseGpa 16, ByteCount 24, ControlFlags 32,
//     write DataBuffer[16] 40; sizes 40/56. Output Status 0, padding 4..7,
//     AccessResult 8, read DataBuffer[16] 16; sizes 32/16.
// All paths above are under onecore/hv/. test/common/tf/testcase/tftestcase.cpp adds the
// header before the native input. nt/winhv/kernel/winhvkt.cpp returns exact
// output sizes even when the nested WinHv status fails. No OS source changes
// or static winhvtf.lib-as-DLL calls are involved.
const (
	protectedSharedHvIOCTLCode       uint32 = (2 << 2) | 1
	protectedSharedHvReadID          uint32 = (101 << 16) | 35
	protectedSharedHvWriteID         uint32 = (101 << 16) | 36
	protectedSharedHvHeaderSize            = 16
	protectedSharedHvReadInputSize         = 40
	protectedSharedHvWriteInputSize        = 56
	protectedSharedHvReadOutputSize        = 32
	protectedSharedHvWriteOutputSize       = 16

	// hvx/inc/HvAmApi.h defines CacheType byte 0 (WriteBack=6), InputVtl
	// byte 1; published/hvgdk_mini.w HV_INPUT_VTL has TargetVtl bits 0..3,
	// UseTargetVtl bit 4. Explicit target VTL0 is therefore 0x10, not zero.
	protectedSharedHvControlFlags uint64 = 6 | (0x10 << 8)

	// hvx/am/gpa/GpaProtectedShared.c GpaCheckExternalGpaAccess returns
	// HV_STATUS_ACCESS_DENIED=6 (published/hvgdk_mini.w). drv/winhv/am.c
	// uses WinHvpFunctorExecute -> WinHvpHypercall -> WinHvpHypercallRoutine
	// in drv/winhv/hypercall.c -> HVSTATUS_TO_NTSTATUS in winhvp.h.
	// minkernel/published/base/ntstatus.mc defines Error=3, Hypervisor=0x35
	// and STATUS_HV_ACCESS_DENIED code 6: (3<<30)|(0x35<<16)|6.
	// This is NOT generic STATUS_ACCESS_DENIED, an HRESULT, or install denial.
	protectedSharedHvPolicyDenied uint32 = 0xc0350006
)

// protectedSharedHvTarget borrows a caller-validated owned partition identity
// and one 4-KiB-aligned page GPA. The caller must obtain ID/validity from its
// serialized HCS partition-action outcome, never enumeration or an ID guess.
// Neither these diagnostics nor this struct grant authority to access a VM.
type protectedSharedHvTarget struct {
	partitionID      uint64
	partitionIDValid bool
	pageGPA          uint64
}

// protectedSharedHvProbeResult separates transport framing, native status and
// access-result validity. WinHv publishes AccessResult only on NT_SUCCESS;
// data is usable only for a successful read/access result. Never log data,
// including unexpected successful protected reads; compare synthetic sentinels
// in memory only. Status/validity diagnostics are not attestation.
type protectedSharedHvProbeResult struct {
	transportError    error
	nativeStatusValid bool
	nativeStatus      uint32
	accessResultValid bool
	resultCode        uint32
	bytesProcessed    uint32
	dataValid         bool
	data              [8]byte
}

// protectedSharedHvIOCTL is only a synchronous DeviceIoControl seam for the two
// existing test cases. The function borrows aligned slices for the entire call,
// may fill output, returns actual bytes, and must not retain buffers or handle.
type protectedSharedHvIOCTL func(windows.Handle, uint32, []byte, []byte) (uint32, error)

// protectedSharedHvProbe exclusively owns an already installed driver's handle.
// Callers serialize all reads/writes/Close and keep the VM/target alive through
// each synchronous call. It does not own, create or configure driver/VM/backing.
type protectedSharedHvProbe struct {
	handle windows.Handle
	ioctl  protectedSharedHvIOCTL
}

// openProtectedSharedHvProbe opens only the installed \\.\hvtest with the same
// read/write access and sharing as tfdeviceadapter.cpp. The caller owns Close.
// Unsupported architecture, missing device or ACL errors are prerequisites,
// never a policy-denial result. Call before acquiring backing or starting VMs.
func openProtectedSharedHvProbe() (*protectedSharedHvProbe, error) {
	if runtime.GOARCH != "amd64" {
		return nil, errors.New("hvtest GPA probe prerequisite: Windows AMD64 required")
	}
	name, err := windows.UTF16PtrFromString(`\\.\hvtest`)
	if err != nil {
		return nil, err
	}
	handle, err := windows.CreateFile(name, windows.GENERIC_READ|windows.GENERIC_WRITE,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE, nil, windows.OPEN_EXISTING, 0, 0)
	if err != nil {
		return nil, fmt.Errorf("open installed hvtest GPA probe prerequisite: %w", err)
	}
	return &protectedSharedHvProbe{handle: handle, ioctl: protectedSharedHvDeviceIOCTL}, nil
}

// Close releases the exclusively owned driver handle after synchronous calls
// finish. Failure preserves ownership for retry; nil/already closed is harmless.
// It neither unloads the driver nor closes any VM or backing resources.
func (p *protectedSharedHvProbe) Close() error {
	if p == nil || p.handle == 0 || p.handle == windows.InvalidHandle {
		return nil
	}
	if err := windows.CloseHandle(p.handle); err != nil {
		return fmt.Errorf("close hvtest probe: %w", err)
	}
	p.handle = 0
	return nil
}

// protectedSharedHvDeviceIOCTL borrows handle and nonempty buffers for one
// synchronous existing test IOCTL, without overlapped completion or retention.
// Its returned Win32 error and byte count describe transport only, not WinHv.
func protectedSharedHvDeviceIOCTL(handle windows.Handle, code uint32, input, output []byte) (uint32, error) {
	var returned uint32
	err := windows.DeviceIoControl(handle, code, &input[0], uint32(len(input)),
		&output[0], uint32(len(output)), &returned, nil)
	return returned, err
}

// protectedSharedHvAligned allocates zeroed owned storage and a 16-byte-aligned
// size-byte view. Only small positive fixed protocol sizes are supplied here.
// The storage/view must survive the synchronous IOCTL; no native pointer escapes.
func protectedSharedHvAligned(size int) (storage, view []byte) {
	storage = make([]byte, size+15)
	offset := int((16 - uintptr(unsafe.Pointer(&storage[0]))%16) % 16)
	return storage, storage[offset : offset+size]
}

// encodeProtectedSharedHvRequest fills a fresh zeroed header/native AMD64 frame
// for exactly one eight-byte, inside-page VP0/VTL0 write-back access. It checks
// owned-ID validity, rejects self/invalid IDs, unaligned pages and address
// overflow before encoding. Data is copied only for writes. Errors yield no
// usable request and change no native state; returned bytes belong to caller.
func encodeProtectedSharedHvRequest(target protectedSharedHvTarget, offset uint32, write bool, data [8]byte) ([]byte, error) {
	if !target.partitionIDValid || target.partitionID == 0 || target.partitionID == math.MaxUint64 ||
		target.pageGPA%4096 != 0 || target.pageGPA > math.MaxUint64-4095 || offset > 4096-8 {
		return nil, errors.New("hvtest probe requires owned identity and an eight-byte inside-page GPA")
	}
	size, id := protectedSharedHvReadInputSize, protectedSharedHvReadID
	if write {
		size, id = protectedSharedHvWriteInputSize, protectedSharedHvWriteID
	}
	frame := make([]byte, protectedSharedHvHeaderSize+size)
	binary.LittleEndian.PutUint32(frame[0:4], id)
	input := frame[protectedSharedHvHeaderSize:]
	// Preserve every native alignment gap and all unused data bytes as zero.
	// VpIndex at 8 is explicitly VP0 (the fresh Linux VMs have this VP).
	binary.LittleEndian.PutUint64(input[0:8], target.partitionID)
	binary.LittleEndian.PutUint32(input[8:12], 0)
	binary.LittleEndian.PutUint64(input[16:24], target.pageGPA+uint64(offset))
	binary.LittleEndian.PutUint32(input[24:28], 8)
	binary.LittleEndian.PutUint64(input[32:40], protectedSharedHvControlFlags)
	if write {
		copy(input[40:48], data[:])
	}
	return frame, nil
}

// decodeProtectedSharedHvResult accepts only an exact native output size AFTER
// successful transport. Native status is always available then, but failed
// NTSTATUS leaves all nested access/data fields invalid and uninterpreted.
// Successful access reads copy only the requested eight bytes into owned data;
// no buffer or bytes are formatted into errors, even on unexpected success.
func decodeProtectedSharedHvResult(output []byte, returned uint32, write bool, transportErr error) protectedSharedHvProbeResult {
	r := protectedSharedHvProbeResult{transportError: transportErr}
	if transportErr != nil {
		return r
	}
	size := protectedSharedHvReadOutputSize
	if write {
		size = protectedSharedHvWriteOutputSize
	}
	if len(output) != size || returned != uint32(size) {
		r.transportError = fmt.Errorf("hvtest GPA protocol size mismatch: buffer=%d returned=%d expected=%d", len(output), returned, size)
		return r
	}
	r.nativeStatusValid = true
	r.nativeStatus = binary.LittleEndian.Uint32(output[0:4])
	// WinHvReadGpa/WriteGpa leave AccessResult untouched on native failure.
	// Never turn zeroed/uninitialized nested output into corroborating evidence.
	if r.nativeStatus&0x80000000 != 0 {
		return r
	}
	r.accessResultValid = true
	r.resultCode = binary.LittleEndian.Uint32(output[8:12])
	r.bytesProcessed = binary.LittleEndian.Uint32(output[12:16])
	if !write && r.nativeStatus == 0 && r.resultCode == 0 {
		copy(r.data[:], output[16:24])
		r.dataValid = true
	}
	return r
}

// access invokes only the existing read/write case, borrowing a live owned
// target. Offset is bytes within its page; eight bytes are always transferred.
// Validation/transport failures stay separate from the nested native status.
// Input/output storage is aligned and retained across the FULL synchronous
// syscall, including the test seam; caller must serialize access versus Close.
func (p *protectedSharedHvProbe) access(target protectedSharedHvTarget, offset uint32, write bool, data [8]byte) protectedSharedHvProbeResult {
	if runtime.GOARCH != "amd64" || p == nil || p.handle == 0 || p.handle == windows.InvalidHandle || p.ioctl == nil {
		return protectedSharedHvProbeResult{transportError: errors.New("hvtest GPA probe prerequisite: unavailable AMD64 driver client")}
	}
	frame, err := encodeProtectedSharedHvRequest(target, offset, write, data)
	if err != nil {
		return protectedSharedHvProbeResult{transportError: err}
	}
	inputStorage, input := protectedSharedHvAligned(len(frame))
	copy(input, frame)
	size := protectedSharedHvReadOutputSize
	if write {
		size = protectedSharedHvWriteOutputSize
	}
	outputStorage, output := protectedSharedHvAligned(size)
	returned, ioctlErr := p.ioctl(p.handle, protectedSharedHvIOCTLCode, input, output)
	runtime.KeepAlive(inputStorage)
	runtime.KeepAlive(outputStorage)
	return decodeProtectedSharedHvResult(output, returned, write, ioctlErr)
}

// read returns the separate transport/native/access outcome for eight bytes.
// After requirePositive succeeds, data is valid for sentinel comparison only;
// never print it. The caller retains target/driver ownership and serialization.
func (p *protectedSharedHvProbe) read(target protectedSharedHvTarget, offset uint32) protectedSharedHvProbeResult {
	return p.access(target, offset, false, [8]byte{})
}

// write copies an eight-byte synthetic value into a synchronous existing WinHv
// write request. The caller owns target/driver lifetime and must validate the
// result; no return value acknowledges success without requirePositive.
func (p *protectedSharedHvProbe) write(target protectedSharedHvTarget, offset uint32, data [8]byte) protectedSharedHvProbeResult {
	return p.access(target, offset, true, data)
}

// requirePositive requires exact native success and HvAccessGpaSuccess, not
// merely transport success. BytesProcessed may be zero for the inline path;
// it is diagnostic, not an eight-byte completion counter. Read callers must
// also compare the known sentinel in memory; no protected bytes enter errors.
func (r protectedSharedHvProbeResult) requirePositive() error {
	if r.transportError != nil {
		return r.transportError
	}
	if !r.nativeStatusValid || r.nativeStatus != 0 {
		return fmt.Errorf("hvtest positive control failed: native-valid=%t status=%#08x",
			r.nativeStatusValid, r.nativeStatus)
	}
	if !r.accessResultValid {
		return errors.New("hvtest positive control lacks a valid access result")
	}
	if r.resultCode != 0 {
		return fmt.Errorf("hvtest positive control failed: access-code=%d", r.resultCode)
	}
	return nil
}

// requirePolicyDenial accepts ONLY the matched converted HV access denial on
// successful exact transport, with no nested fields valid. Generic ACL denial,
// invalid VP/partition, intercepts and unexpected successes fail the experiment.
// It never examines returned bytes or AccessResult on native failure.
func (r protectedSharedHvProbeResult) requirePolicyDenial() error {
	if r.transportError != nil {
		return r.transportError
	}
	if !r.nativeStatusValid || r.nativeStatus != protectedSharedHvPolicyDenied || r.accessResultValid || r.dataValid {
		return fmt.Errorf("hvtest expected exact policy denial: native-valid=%t status=%#08x access-valid=%t",
			r.nativeStatusValid, r.nativeStatus, r.accessResultValid)
	}
	return nil
}
