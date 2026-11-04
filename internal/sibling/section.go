//go:build windows

package sibling

import (
	"errors"
	"fmt"
	"math"
	"strings"
	"sync"
	"unsafe"

	"golang.org/x/sys/windows"
)

type Section struct {
	Name    string
	HCSName string
	Size    uint64
	mu      sync.Mutex
	handle  windows.Handle
	view    uintptr
}

func SectionNames(name string, sessionID uint32) (string, string, error) {
	if name == "" || strings.ContainsAny(name, "\\/\x00") {
		return "", "", fmt.Errorf("shared-memory section name %q must be a simple object name", name)
	}
	return name, fmt.Sprintf(`\Sessions\%d\BaseNamedObjects\%s`, sessionID, name), nil
}

func CreateSection(name string, size uint64) (*Section, error) {
	if size == 0 || size > math.MaxInt32 {
		return nil, errors.New("shared-memory section size must be in 1..MaxInt32")
	}
	var session uint32
	if err := windows.ProcessIdToSessionId(windows.GetCurrentProcessId(), &session); err != nil {
		return nil, err
	}
	name, hcsName, err := SectionNames(name, session)
	if err != nil {
		return nil, err
	}
	namePtr, err := windows.UTF16PtrFromString(name)
	if err != nil {
		return nil, err
	}
	sd, err := windows.SecurityDescriptorFromString("D:P(A;;GA;;;WD)")
	if err != nil {
		return nil, err
	}
	attributes := &windows.SecurityAttributes{
		Length: uint32(unsafe.Sizeof(windows.SecurityAttributes{})), SecurityDescriptor: sd,
	}
	handle, err := windows.CreateFileMapping(windows.InvalidHandle, attributes,
		windows.PAGE_READWRITE, uint32(size>>32), uint32(size), namePtr)
	if err != nil {
		if handle != 0 {
			_ = windows.CloseHandle(handle)
		}
		return nil, fmt.Errorf("create sibling section: %w", err)
	}
	view, err := windows.MapViewOfFile(handle, windows.FILE_MAP_READ|windows.FILE_MAP_WRITE, 0, 0, uintptr(size))
	if err != nil {
		_ = windows.CloseHandle(handle)
		return nil, err
	}
	section := &Section{Name: name, HCSName: hcsName, Size: size, handle: handle, view: view}
	if err := section.Write(0, []byte("HCSHMEM1-HOST-SEED")); err != nil {
		_ = section.Close()
		return nil, err
	}
	return section, nil
}

func (s *Section) Close() error {
	if s == nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	var err error
	if s.view != 0 {
		err = windows.UnmapViewOfFile(s.view)
		s.view = 0
	}
	if s.handle != 0 {
		err = errors.Join(err, windows.CloseHandle(s.handle))
		s.handle = 0
	}
	return err
}

func (s *Section) Write(offset uint64, data []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.view == 0 || offset > s.Size || uint64(len(data)) > s.Size-offset {
		return errors.New("shared-memory write is unmapped or out of bounds")
	}
	if len(data) == 0 {
		return nil
	}
	var written uintptr
	if err := windows.WriteProcessMemory(windows.CurrentProcess(), s.view+uintptr(offset), &data[0], uintptr(len(data)), &written); err != nil {
		return err
	}
	if written != uintptr(len(data)) {
		return errors.New("short shared-memory write")
	}
	return nil
}

func (s *Section) Read(offset, length uint64) ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.view == 0 || offset > s.Size || length > s.Size-offset {
		return nil, errors.New("shared-memory read is unmapped or out of bounds")
	}
	data := make([]byte, int(length))
	if length == 0 {
		return data, nil
	}
	var read uintptr
	if err := windows.ReadProcessMemory(windows.CurrentProcess(), s.view+uintptr(offset), &data[0], uintptr(length), &read); err != nil {
		return nil, err
	}
	if read != uintptr(length) {
		return nil, errors.New("short shared-memory read")
	}
	return data, nil
}
