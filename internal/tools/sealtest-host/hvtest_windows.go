//go:build windows

package main

import (
	"encoding/binary"
	"errors"
	"fmt"
	"runtime"
	"unsafe"

	"golang.org/x/sys/windows"
)

const (
	pageSize       = 4096
	maxByteGPA     = 1 << 52 // HV_MAX_CHILD_PHYSICAL_ADDRESS_WIDTH, AMD64
	self           = ^uint64(0)
	ioctlUtil      = (1 << 2) | 1
	oidRaw         = 4
	oidBacking     = 31
	objMethod      = 2
	backingVersion = 1
	backingIn      = 128
	backingOut     = 168

	// Published hypercall codes and HvStatus.h, not converted NTSTATUS.
	callWeight        = 0x0044
	callChild         = 0x0047
	callMapContiguous = 0x004b
	callUnmap         = 0x004c
	callDeletePort    = 0x0058
	callDisconnect    = 0x005b
	callMapSparse     = 0x006e
	callCreatePort    = 0x0095
	callConnect       = 0x0096
	callVisibility    = 0x00db
	callMapGHCB       = 0x00e1
	callUnmapGHCB     = 0x00e2
	statusDenied      = 0x0008
)

const (
	opCapabilities uint32 = iota + 1
	opAllocate
	opQuery
	opMap
	opUnmap
	opRelease
)

const (
	stateReady uint32 = iota + 1
	stateInFlight
	stateMapped
	stateUnmapped
	stateNoEffect
	stateQuarantined
	stateReleased
)

var le = binary.LittleEndian

type device windows.Handle

type observation struct {
	TransportOK  bool    `json:"transport_ok"`
	FrameValid   bool    `json:"frame_valid"`
	Returned     uint32  `json:"returned_bytes"`
	Call         uint32  `json:"call_code"`
	Status       *uint32 `json:"hv_status,omitempty"`
	Requested    uint32  `json:"requested_rep"`
	Progress     *uint32 `json:"rep_progress,omitempty"`
	ReadbackKind string  `json:"readback_kind,omitempty"`
	OutputValid  bool    `json:"output_valid"`
	Value        *uint64 `json:"value,omitempty"`
}

type binding struct {
	Instance  [16]byte  `json:"instance"`
	Cookie    uint64    `json:"cookie"`
	Partition uint64    `json:"partition_id"`
	GPAs      [2]uint64 `json:"gpas"`
	Digest    [32]byte  `json:"fixture_digest"`
	Case      uint32    `json:"case"`
	Phase     uint32    `json:"phase"`
}

type backingReply struct {
	binding
	Operation   uint32      `json:"operation"`
	State       uint32      `json:"state"`
	Used        uint32      `json:"pages_used"`
	Known       uint32      `json:"known_mapped"`
	Maybe       uint32      `json:"maybe_mapped"`
	Sequence    uint64      `json:"sequence"`
	NativeValid bool        `json:"native_valid"`
	Dispatched  bool        `json:"dispatched"`
	Recorded    bool        `json:"recorded_observation"`
	Native      observation `json:"native"`
}

// requireHost refuses non-AMD64 Windows hosts, including x64 emulation, and
// requires elevation before reading or creating a diagnostic session.
func requireHost() error {
	if runtime.GOARCH != "amd64" || !windows.GetCurrentProcessToken().IsElevated() {
		return errors.New("requires an elevated Windows AMD64 process")
	}
	const imageFileMachineAMD64 = 0x8664
	var processMachine, nativeMachine uint16
	if err := windows.IsWow64Process2(windows.CurrentProcess(), &processMachine, &nativeMachine); err != nil {
		return fmt.Errorf("verify native Windows architecture: %w", err)
	}
	if processMachine != 0 || nativeMachine != imageFileMachineAMD64 {
		return errors.New("requires native Windows AMD64, not emulation")
	}
	return nil
}

// openDevice opens only the single present, installed interface after requireHost.
func openDevice() (device, error) {
	guid := windows.GUID{Data1: 0x795e12bd, Data2: 0x1d51, Data3: 0x4e15, Data4: [8]byte{0x9f, 0x8a, 0x4b, 0xad, 0x23, 0xd6, 0xbb, 0x4d}}
	paths, err := windows.CM_Get_Device_Interface_List("", &guid, windows.CM_GET_DEVICE_INTERFACE_LIST_PRESENT)
	if err != nil {
		return 0, err
	}
	if len(paths) != 1 || paths[0] == "" {
		return 0, fmt.Errorf("require one present hvtest interface, found %d", len(paths))
	}
	path, err := windows.UTF16PtrFromString(paths[0])
	if err != nil {
		return 0, err
	}
	h, err := windows.CreateFile(path, windows.GENERIC_READ|windows.GENERIC_WRITE, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE, nil, windows.OPEN_EXISTING, 0, 0)
	return device(h), err
}

// aligned returns a view into owned storage whose first byte is page aligned.
func aligned(n int) (storage, view []byte) {
	storage = make([]byte, n+pageSize-1)
	offset := int(-uintptr(unsafe.Pointer(&storage[0])) & (pageSize - 1))
	return storage, storage[offset : offset+n]
}

// raw submits a closed internal call with the header-page/payload-page framing.
// Native status is valid after exact framing; native output needs success too.
func (d device) raw(code uint32, input []byte, count uint32, outputKind string) (o observation, err error) {
	o.Call, o.Requested, o.ReadbackKind = code, count, outputKind
	outputSize := 0
	if outputKind != "" {
		outputSize = 8
	}
	// Match TfUtil::Hypercall: reserve full pages; header sizes describe the
	// actual native payloads, not the lengths submitted to DeviceIoControl.
	inOwner, in := aligned(2 * pageSize)
	outLength := pageSize
	if outputSize != 0 {
		outLength += pageSize
	}
	outOwner, out := aligned(outLength)
	le.PutUint32(in, oidRaw)
	le.PutUint32(in[4:], objMethod)
	le.PutUint16(in[8:], uint16(code))
	le.PutUint32(in[12:], uint32(len(input)))
	le.PutUint32(in[16:], uint32(outputSize))
	le.PutUint32(in[20:], count)
	copy(in[pageSize:], input)
	err = windows.DeviceIoControl(windows.Handle(d), ioctlUtil, &in[0], uint32(len(in)), &out[0], uint32(len(out)), &o.Returned, nil)
	runtime.KeepAlive(inOwner)
	runtime.KeepAlive(outOwner)
	if err != nil {
		return o, fmt.Errorf("hvtest raw utility: %w", err)
	}
	o.TransportOK = true
	if int(o.Returned) != len(out) {
		return o, fmt.Errorf("raw utility reply length %d, want %d", o.Returned, len(out))
	}
	status, progress := uint32(le.Uint16(out)), le.Uint32(out[4:])
	o.Status = &status
	if count != 0 {
		o.Progress = &progress
	}
	if progress > count {
		return o, fmt.Errorf("invalid REP progress %d/%d", progress, count)
	}
	o.FrameValid = true
	if status == 0 && outputSize != 0 {
		value := le.Uint64(out[pageSize:])
		o.Value = &value
		o.OutputValid = outputKind != "parent-map-location-page" || (value != 0 && value < maxByteGPA/pageSize)
	}
	return o, nil
}

// children returns a complete bounded snapshot, not an active-state check.
func (d device) children() ([]uint64, error) {
	ids := make([]uint64, 0)
	seen := make(map[uint64]bool)
	input := make([]byte, 16)
	le.PutUint64(input, self)
	for {
		o, err := d.raw(callChild, input, 0, "next-child")
		if err != nil {
			return nil, err
		}
		if !o.OutputValid {
			return nil, fmt.Errorf("child enumeration HV_STATUS=%#x", *o.Status)
		}
		next := *o.Value
		if next == 0 {
			return ids, nil
		}
		if next == self || seen[next] || len(ids) == 65536 {
			return nil, errors.New("bad, repeated or excessive child enumeration result")
		}
		seen[next] = true
		ids = append(ids, next)
		le.PutUint64(input[8:], next)
	}
}

// activeChild requires explicit membership followed by the regular CpuWeight
// property. The weight itself is ignored; the snapshot pins no partition.
func (d device) activeChild(partition uint64) error {
	if partition == 0 || partition == self {
		return errors.New("invalid explicit child")
	}
	children, err := d.children()
	if err != nil {
		return err
	}
	for _, id := range children {
		if id == partition {
			input := make([]byte, 16)
			le.PutUint64(input, partition)
			le.PutUint32(input[8:], 0x00020003)
			o, err := d.raw(callWeight, input, 0, "cpu-weight")
			if err != nil {
				return err
			}
			if !o.OutputValid {
				return fmt.Errorf("active child prerequisite: CpuWeight HV_STATUS=%#x", *o.Status)
			}
			return nil
		}
	}
	return fmt.Errorf("partition %#x is not an enumerated child", partition)
}

// backing uses the fixed private wire ABI. A Query or Release reply's native
// fields are historical, never a new map/unmap result.
func (d device) backing(op, index uint32, b binding) (r backingReply, wire observation, err error) {
	in := make([]byte, backingIn)
	out := make([]byte, backingOut)
	for i, value := range []uint32{oidBacking, objMethod, backingVersion, backingIn, op, b.Case, b.Phase, index} {
		le.PutUint32(in[i*4:], value)
	}
	copy(in[32:48], b.Instance[:])
	le.PutUint64(in[48:], b.Cookie)
	le.PutUint64(in[56:], b.Partition)
	le.PutUint64(in[64:], b.GPAs[0])
	le.PutUint64(in[72:], b.GPAs[1])
	copy(in[80:112], b.Digest[:])
	err = windows.DeviceIoControl(windows.Handle(d), ioctlUtil, &in[0], uint32(len(in)), &out[0], uint32(len(out)), &wire.Returned, nil)
	runtime.KeepAlive(in)
	runtime.KeepAlive(out)
	if err != nil {
		return r, wire, fmt.Errorf("hvtest backing utility (matching driver required): %w", err)
	}
	wire.TransportOK = true
	if wire.Returned != backingOut || le.Uint32(out) != backingVersion ||
		le.Uint32(out[4:]) != backingOut || le.Uint32(out[8:]) != op ||
		le.Uint32(out[104:]) != 0x3f || le.Uint32(out[108:]) != 4 ||
		le.Uint32(out[112:]) != 8 || le.Uint64(out[160:]) != 0 {
		return r, wire, errors.New("incompatible backing ABI reply")
	}
	r.Operation, r.State = op, le.Uint32(out[12:])
	copy(r.Instance[:], out[16:32])
	r.Cookie, r.Partition = le.Uint64(out[32:]), le.Uint64(out[40:])
	r.GPAs = [2]uint64{le.Uint64(out[48:]), le.Uint64(out[56:])}
	copy(r.Digest[:], out[64:96])
	r.Case, r.Phase, r.Used = le.Uint32(out[96:]), le.Uint32(out[100:]), le.Uint32(out[116:])
	nv, dispatched := le.Uint32(out[120:]), le.Uint32(out[124:])
	code, count, status, progress := le.Uint32(out[128:]), le.Uint32(out[132:]), le.Uint32(out[136:]), le.Uint32(out[140:])
	r.Known, r.Maybe, r.Sequence = le.Uint32(out[144:]), le.Uint32(out[148:]), le.Uint64(out[152:])
	want := b
	if op == opCapabilities {
		want.Instance = r.Instance
	} else if b.Cookie == 0 {
		want.Cookie = r.Cookie
	}
	if r.binding != want || r.Instance == ([16]byte{}) || r.Used > 8 || r.Used%2 != 0 ||
		nv > 1 || dispatched > 1 || (dispatched == 1) != (op == opMap || op == opUnmap) ||
		r.Known|r.Maybe > 3 || r.Known&r.Maybe != 0 || (op != opCapabilities && r.Cookie == 0) {
		return r, wire, errors.New("backing reply changed binding or has inconsistent metadata")
	}
	r.NativeValid, r.Dispatched = nv == 1, dispatched == 1
	if r.Sequence == 0 {
		if code|count|status|progress != 0 || r.NativeValid || r.Dispatched {
			return r, wire, errors.New("invalid absent native observation")
		}
	} else {
		mapCode := uint32(callMapContiguous)
		if b.Case == 2 {
			mapCode = callMapSparse
		}
		if !((code == mapCode && count == 2 && r.Sequence == 1) ||
			(code == callUnmap && count == 1 && (r.Sequence == 2 || r.Sequence == 3) && b.Phase == 1)) ||
			(op == opMap && code != mapCode) || (op == opUnmap && code != callUnmap) ||
			status > 0xffff || progress > 0xfff || (r.NativeValid && progress > count) {
			return r, wire, errors.New("invalid backing native observation metadata")
		}
		r.Recorded = !r.Dispatched
		r.Native = observation{FrameValid: r.NativeValid, Call: code, Requested: count, Status: &status, Progress: &progress}
	}
	complete := r.NativeValid && status == 0 && progress == count
	clear := r.Known|r.Maybe == 0
	validState := false
	switch r.State {
	case 0:
		validState = op == opCapabilities && r.Sequence == 0 && clear
	case stateReady:
		validState = (op == opAllocate || op == opQuery) && r.Sequence == 0 && clear
	case stateMapped:
		validState = (op == opQuery || op == opMap || op == opUnmap) &&
			b.Phase == 1 && complete && r.Maybe == 0 &&
			((r.Sequence == 1 && r.Known == 3) || (r.Sequence == 2 && (r.Known == 1 || r.Known == 2)))
	case stateUnmapped:
		validState = (op == opQuery || op == opUnmap) && complete && r.Sequence == 3 && clear
	case stateNoEffect:
		validState = (op == opQuery || op == opMap) && r.NativeValid && status == statusDenied && progress == 0 && r.Sequence == 1 && clear
	case stateQuarantined:
		validState = (op == opQuery || op == opMap || op == opUnmap) &&
			((r.Sequence == 1 && ((complete && b.Phase == 2 && r.Known == 3 && r.Maybe == 0) ||
				(!complete && r.Known == 0 && r.Maybe == 3))) ||
				(!complete && r.Sequence == 2 && r.Known|r.Maybe == 3 && (r.Maybe == 1 || r.Maybe == 2)) ||
				(!complete && r.Sequence == 3 && r.Known == 0 && (r.Maybe == 1 || r.Maybe == 2)))
	case stateReleased:
		validState = op == opRelease && clear && (r.Sequence == 0 ||
			(complete && r.Sequence == 3) || (r.NativeValid && status == statusDenied && progress == 0 && r.Sequence == 1))
	}
	if op != opCapabilities && op != opRelease && r.Used < 2 {
		validState = false
	}
	if !validState {
		return r, wire, errors.New("invalid backing lifetime state")
	}
	wire.FrameValid = true
	return r, wire, nil
}

// unmapInput targets exactly one already selected guest destination page.
func unmapInput(target, gpa uint64) []byte {
	input := make([]byte, 24)
	le.PutUint64(input, target)
	le.PutUint64(input[8:], gpa/pageSize)
	return input
}
