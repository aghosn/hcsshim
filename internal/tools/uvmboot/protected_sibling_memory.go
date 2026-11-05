//go:build windows

package main

import (
	"context"
	"errors"
	"fmt"
	"math"
	"runtime"
	"syscall"
	"time"
	"unsafe"

	"github.com/Microsoft/hcsshim/internal/computecore"
	hcsv2 "github.com/Microsoft/hcsshim/internal/hcs/v2"
	"golang.org/x/sys/windows"
)

const (
	protectedPageBytes = 4096

	// SharedMemoryRegion.Length is signed int32 bytes; retain only whole pages.
	protectedMaxBytes  = math.MaxInt32 & ^(protectedPageBytes - 1)
	protectedSeal      = 2
	protectedTeardown  = 3
	protectedReclaim   = 4
	protectedBusy      = uint32(0x80000011)
	protectedInUse     = uint32(0xc0350019)
)

// protectedControlRequest/Result match VidDefs.h's compact v2 ABI. Indices and
// counts are 4-KiB pages, not bytes. Lifetime zero uses VID-owned descriptors.
// Version zero in a result is unknown progress, never a zero-work receipt.
type protectedControlRequest struct {
	Version, Flags                uint32
	LeaseID, PageIndex, LifetimeID uint64
	PageCount, Operation          uint32
	Reserved                      uint64
}

type protectedControlResult struct {
	Version, Size, Status, Processed uint32
	LeaseID, PageCount, Initialized  uint64
}

// protectedSiblingMemory is a route-private concrete capability owner. There
// is deliberately no ordinary Section embedding, content accessor or Close.
// The pair goroutine exclusively owns all fields and serializes native calls.
// blocked is set BEFORE Bootstrap create dispatch; unknown is sticky. Only
// explicit, fully framed reclaim permits a temporary verification view and
// release. Cached startup receipts establish history, not release authority.
type protectedSiblingMemory struct {
	section, controller windows.Handle
	control             *windows.LazyProc
	hcsName             string
	size, pages         uint64
	lease, initialized  uint64
	sealed, teardown    uint64
	reclaimed           uint64
	zeroVerifiedBytes   uint64
	blocked, unknown    bool
	resource            hcsv2.OperationResource
}

// validateProtectedControllerABI rejects unsupported architecture/layout before
// acquiring native resources. Every offset follows current VidDefs.h; it does
// not establish deployed DLL provenance, which remains a manual prerequisite.
func validateProtectedControllerABI() error {
	if runtime.GOARCH != "amd64" ||
		unsafe.Sizeof(protectedControlRequest{}) != 48 ||
		unsafe.Offsetof(protectedControlRequest{}.Version) != 0 ||
		unsafe.Offsetof(protectedControlRequest{}.Flags) != 4 ||
		unsafe.Offsetof(protectedControlRequest{}.LeaseID) != 8 ||
		unsafe.Offsetof(protectedControlRequest{}.PageIndex) != 16 ||
		unsafe.Offsetof(protectedControlRequest{}.LifetimeID) != 24 ||
		unsafe.Offsetof(protectedControlRequest{}.PageCount) != 32 ||
		unsafe.Offsetof(protectedControlRequest{}.Operation) != 36 ||
		unsafe.Offsetof(protectedControlRequest{}.Reserved) != 40 ||
		unsafe.Sizeof(protectedControlResult{}) != 40 ||
		unsafe.Offsetof(protectedControlResult{}.Version) != 0 ||
		unsafe.Offsetof(protectedControlResult{}.Size) != 4 ||
		unsafe.Offsetof(protectedControlResult{}.Status) != 8 ||
		unsafe.Offsetof(protectedControlResult{}.Processed) != 12 ||
		unsafe.Offsetof(protectedControlResult{}.LeaseID) != 16 ||
		unsafe.Offsetof(protectedControlResult{}.PageCount) != 24 ||
		unsafe.Offsetof(protectedControlResult{}.Initialized) != 32 {
		return errors.New("unsupported AMD64 VID v2 controller ABI")
	}
	return nil
}

// newProtectedSiblingMemory creates fresh pagefile backing and an independent
// VID controller. size is page-aligned bytes within the signed schema bound.
// name must be a unique simple object name. No content view, seed, or pin is
// acquired here; native allocation/admission can still reject the geometry.
// On error all acquisitions made here are closed; success transfers ownership
// to the pair. Session zero uses the actual global BaseNamedObjects directory,
// not the ordinary helper's synthetic Sessions/0 path.
func newProtectedSiblingMemory(name string, size uint64) (*protectedSiblingMemory, error) {
	if err := validateProtectedControllerABI(); err != nil {
		return nil, err
	}
	if size == 0 || size%protectedPageBytes != 0 || size > protectedMaxBytes {
		return nil, fmt.Errorf("protected backing requires page-aligned bytes in %d..%d", protectedPageBytes, protectedMaxBytes)
	}
	var session uint32
	if err := windows.ProcessIdToSessionId(windows.GetCurrentProcessId(), &session); err != nil {
		return nil, err
	}
	objectName, hcsName, err := sharedMemorySectionNames(name, session)
	if err != nil {
		return nil, err
	}
	if session == 0 {
		hcsName = `\BaseNamedObjects\` + objectName
	}
	dll := windows.NewLazySystemDLL("vid.dll")
	create := dll.NewProc("VidCreateProtectedSharedController")
	control := dll.NewProc("VidControlProtectedShared")
	if err := create.Find(); err != nil {
		return nil, fmt.Errorf("matched VID controller export: %w", err)
	}
	if err := control.Find(); err != nil {
		return nil, fmt.Errorf("matched VID control export: %w", err)
	}
	nameUTF16, err := windows.UTF16PtrFromString(objectName)
	if err != nil {
		return nil, err
	}
	// Match the existing lab section's worker-access ACL. This is not a
	// confidentiality boundary: trusted initialization revokes RP access,
	// while native section/controller validation supplies attachment authority.
	sd, err := windows.SecurityDescriptorFromString("D:P(A;;GA;;;WD)")
	if err != nil {
		return nil, err
	}
	attributes := &windows.SecurityAttributes{
		Length: uint32(unsafe.Sizeof(windows.SecurityAttributes{})), SecurityDescriptor: sd,
	}
	section, err := windows.CreateFileMapping(windows.InvalidHandle, attributes,
		windows.PAGE_READWRITE, 0, uint32(size), nameUTF16)
	if err != nil {
		// ERROR_ALREADY_EXISTS also returns a handle. Never import an old
		// object, even when its size or apparently fresh contents match.
		if section != 0 {
			err = errors.Join(err, windows.CloseHandle(section))
		}
		return nil, fmt.Errorf("create fresh protected section: %w", err)
	}
	handle, _, callErr := create.Call()
	controller := windows.Handle(handle)
	if controller == 0 || controller == windows.InvalidHandle {
		return nil, errors.Join(fmt.Errorf("create VID controller: %v", callErr), windows.CloseHandle(section))
	}
	return &protectedSiblingMemory{
		section: section, controller: controller, control: control,
		hcsName: hcsName, size: size, pages: size / protectedPageBytes,
		resource: hcsv2.OperationResource{
			Type: computecore.HcsResourceTypeFile, URI: "hcs:/ProtectedSibling/" + name,
			Handle: syscall.Handle(controller),
		},
	}, nil
}

// controlBatch submits one bounded admission/cleanup request, borrowing buffers
// and the retained controller through synchronous native completion. ctx bounds
// submission and subsequent batches, not an already executing kernel call.
// Framed prefixes are returned even on errors; malformed output makes unknown
// sticky. No goroutine abandons live native buffers on cancellation. Callers
// consume Processed before errors and never replay partial/unknown progress.
func (m *protectedSiblingMemory) controlBatch(ctx context.Context, operation uint32, index uint64, count uint32) (protectedControlResult, error) {
	var result protectedControlResult
	if err := ctx.Err(); err != nil {
		return result, err
	}
	if operation < protectedSeal || operation > protectedReclaim || m.lease == 0 ||
		count == 0 || count > 4 || index >= m.initialized || uint64(count) > m.initialized-index {
		return result, errors.New("invalid protected controller batch")
	}
	request := protectedControlRequest{
		Version: 2, Flags: 1, LeaseID: m.lease, PageIndex: index,
		PageCount: count, Operation: operation,
	}
	ok, _, callErr := m.control.Call(uintptr(m.controller),
		uintptr(unsafe.Pointer(&request)), uintptr(unsafe.Pointer(&result)))
	runtime.KeepAlive(m)
	runtime.KeepAlive(request)
	runtime.KeepAlive(result)
	shortSuccess := result.Status&0x80000000 == 0 && result.Processed < count
	if result.Version != 2 || result.Size != 40 || result.LeaseID != m.lease ||
		result.PageCount != m.pages || result.Initialized != m.initialized || result.Processed > count ||
		(ok != 0 && ok != 1) ||
		(((ok == 0) != (result.Status&0x80000000 != 0)) && !(ok == 0 && shortSuccess)) {
		m.unknown = true
		return protectedControlResult{}, fmt.Errorf("unframed VID control operation=%d API=%d: %v", operation, ok, callErr)
	}
	if ok == 0 || result.Status != 0 || result.Processed != count {
		return result, fmt.Errorf("VID control operation=%d index=%d count=%d processed=%d status=%#08x API=%d: %v",
			operation, index, count, result.Processed, result.Status, ok, callErr)
	}
	return result, nil
}

// advance performs the remaining contiguous prefix for exactly one lifecycle
// phase. prefix uses pages and remains valid on error. Only framed zero-progress
// reclaim contention is retried, within ctx; partial or unframed failures stop.
// Caller serialization is required. Each page is sealed only once per backing,
// independently of the number of participants or their GPA assignments.
func (m *protectedSiblingMemory) advance(ctx context.Context, operation uint32, prefix *uint64) error {
	for *prefix < m.initialized {
		count := uint32(min(uint64(4), m.initialized-*prefix))
		result, err := m.controlBatch(ctx, operation, *prefix, count)
		if result.Version == 2 {
			*prefix += uint64(result.Processed)
		}
		if err != nil {
			if operation == protectedReclaim && result.Version == 2 && result.Processed == 0 &&
				(result.Status == protectedBusy || result.Status == protectedInUse) {
				timer := time.NewTimer(100 * time.Millisecond)
				select {
				case <-ctx.Done():
					timer.Stop()
					return errors.Join(err, ctx.Err())
				case <-timer.C:
					continue
				}
			}
			return err
		}
		if err := ctx.Err(); err != nil {
			return err
		}
	}
	return nil
}

// release verifies every initialized byte is zero ONLY after actual full
// reclaim, then closes controller/section. Before Bootstrap dispatch an empty
// owner can also be released without a content read. Unknown progress prevents
// either action. The caller must first drain all owned VM attempts; this method
// is private to the pair cleanup and is not an ordinary unconditional Close.
// Failed verification retains handles; native close failures are returned.
func (m *protectedSiblingMemory) release(ctx context.Context) error {
	if m.unknown || (m.blocked && (m.initialized != m.pages || m.reclaimed != m.initialized)) {
		return errors.New("protected release denied: unknown progress or incomplete reclaim")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if m.blocked {
		view, err := windows.MapViewOfFile(m.section, windows.FILE_MAP_READ, 0, 0, uintptr(m.size))
		if err != nil {
			return fmt.Errorf("map authorized reclaimed backing: %w", err)
		}
		var verifyErr error
		// This view is never retained across a protected dispatch. Full reclaim
		// is the authority for access, not an old Install/Remove cache.
		data := unsafe.Slice((*byte)(unsafe.Pointer(view)), int(m.initialized*protectedPageBytes))
		for i, value := range data {
			if value != 0 {
				verifyErr = fmt.Errorf("reclaimed protected backing is nonzero at byte %d", i)
				break
			}
		}
		verifyErr = errors.Join(verifyErr, windows.UnmapViewOfFile(view), ctx.Err())
		if verifyErr != nil {
			return verifyErr
		}
		m.zeroVerifiedBytes = m.initialized * protectedPageBytes
	}
	var err error
	if m.controller != 0 {
		if closeErr := windows.CloseHandle(m.controller); closeErr != nil {
			err = errors.Join(err, closeErr)
		} else {
			m.controller = 0
		}
	}
	if m.section != 0 {
		if closeErr := windows.CloseHandle(m.section); closeErr != nil {
			err = errors.Join(err, closeErr)
		} else {
			m.section = 0
		}
	}
	return err
}
