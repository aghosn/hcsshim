//go:build windows

package main

import (
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"
	"math"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
)

type sharedMemorySection struct {
	handle  windows.Handle
	name    string
	hcsName string
	size    uint64
	view    uintptr
}

func createSharedMemorySection(name string, size uint64) (*sharedMemorySection, error) {
	if name == "" {
		return nil, errors.New("shared-memory section name is empty")
	}
	if size == 0 {
		return nil, errors.New("shared-memory section size must be greater than zero")
	}
	if size > math.MaxInt32 {
		return nil, fmt.Errorf(
			"shared-memory section size %d exceeds HCS schema limit %d",
			size,
			math.MaxInt32,
		)
	}

	var sessionID uint32
	if err := windows.ProcessIdToSessionId(
		windows.GetCurrentProcessId(),
		&sessionID,
	); err != nil {
		return nil, fmt.Errorf("resolve current process session: %w", err)
	}

	win32Name, hcsName, err := sharedMemorySectionNames(name, sessionID)
	if err != nil {
		return nil, err
	}

	namePtr, err := windows.UTF16PtrFromString(win32Name)
	if err != nil {
		return nil, fmt.Errorf("encode shared-memory section name: %w", err)
	}

	securityDescriptor, err := windows.SecurityDescriptorFromString(
		"D:P(A;;GA;;;WD)",
	)
	if err != nil {
		return nil, fmt.Errorf("create shared-memory security descriptor: %w", err)
	}
	securityAttributes := &windows.SecurityAttributes{
		Length:             uint32(unsafe.Sizeof(windows.SecurityAttributes{})),
		SecurityDescriptor: securityDescriptor,
	}

	handle, err := windows.CreateFileMapping(
		windows.InvalidHandle,
		securityAttributes,
		windows.PAGE_READWRITE,
		uint32(size>>32),
		uint32(size),
		namePtr,
	)
	if err != nil {
		if handle != 0 {
			_ = windows.CloseHandle(handle)
		}
		return nil, fmt.Errorf(
			"create shared-memory section %q: %w",
			win32Name,
			err,
		)
	}

	view, err := windows.MapViewOfFile(
		handle,
		windows.FILE_MAP_READ|windows.FILE_MAP_WRITE,
		0,
		0,
		uintptr(size),
	)
	if err != nil {
		_ = windows.CloseHandle(handle)
		return nil, fmt.Errorf(
			"map shared-memory section %q into host: %w",
			win32Name,
			err,
		)
	}

	section := &sharedMemorySection{
		handle:  handle,
		name:    win32Name,
		hcsName: hcsName,
		size:    size,
		view:    view,
	}
	if err := section.write(0, []byte("HCSHMEM1-HOST-SEED")); err != nil {
		_ = section.Close()
		return nil, err
	}

	return section, nil
}

func sharedMemorySectionNames(name string, sessionID uint32) (string, string, error) {
	if strings.ContainsAny(name, `\/`) {
		return "", "", fmt.Errorf(
			"shared-memory section name %q must be a simple object name",
			name,
		)
	}

	return name, fmt.Sprintf(
		`\Sessions\%d\BaseNamedObjects\%s`,
		sessionID,
		name,
	), nil
}

func (s *sharedMemorySection) Close() error {
	if s == nil {
		return nil
	}

	var closeErr error
	if s.view != 0 {
		if err := windows.UnmapViewOfFile(s.view); err != nil {
			closeErr = fmt.Errorf(
				"unmap shared-memory section %q: %w",
				s.name,
				err,
			)
		}
		s.view = 0
	}
	if s.handle != 0 {
		if err := windows.CloseHandle(s.handle); err != nil && closeErr == nil {
			closeErr = fmt.Errorf(
				"close shared-memory section %q: %w",
				s.name,
				err,
			)
		}
		s.handle = 0
	}
	return closeErr
}

func (s *sharedMemorySection) write(offset uint64, data []byte) error {
	if s == nil || s.view == 0 {
		return errors.New("shared-memory section is not mapped")
	}
	if offset > s.size || uint64(len(data)) > s.size-offset {
		return fmt.Errorf(
			"shared-memory write [%d,%d) exceeds section size %d",
			offset,
			offset+uint64(len(data)),
			s.size,
		)
	}

	if len(data) == 0 {
		return nil
	}

	process, err := windows.GetCurrentProcess()
	if err != nil {
		return fmt.Errorf("get current process handle: %w", err)
	}
	var written uintptr
	if err := windows.WriteProcessMemory(
		process,
		s.view+uintptr(offset),
		&data[0],
		uintptr(len(data)),
		&written,
	); err != nil {
		return fmt.Errorf("write shared-memory section %q: %w", s.name, err)
	}
	if written != uintptr(len(data)) {
		return fmt.Errorf(
			"write shared-memory section %q: wrote %d of %d bytes",
			s.name,
			written,
			len(data),
		)
	}
	return nil
}

func (s *sharedMemorySection) hexPrefix(length uint64) (string, error) {
	data, err := s.read(0, length)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(data), nil
}

func (s *sharedMemorySection) expect(offset uint64, expected []byte) error {
	actual, err := s.read(offset, uint64(len(expected)))
	if err != nil {
		return err
	}
	if !bytes.Equal(actual, expected) {
		return fmt.Errorf(
			"shared-memory marker mismatch at offset %d: got %x, expected %x",
			offset,
			actual,
			expected,
		)
	}
	return nil
}

func (s *sharedMemorySection) read(offset, length uint64) ([]byte, error) {
	if s == nil || s.view == 0 {
		return nil, errors.New("shared-memory section is not mapped")
	}
	if offset > s.size || length > s.size-offset {
		return nil, fmt.Errorf(
			"shared-memory read [%d,%d) exceeds section size %d",
			offset,
			offset+length,
			s.size,
		)
	}
	if length == 0 {
		return nil, nil
	}

	data := make([]byte, int(length))
	process, err := windows.GetCurrentProcess()
	if err != nil {
		return nil, fmt.Errorf("get current process handle: %w", err)
	}
	var read uintptr
	if err := windows.ReadProcessMemory(
		process,
		s.view+uintptr(offset),
		&data[0],
		uintptr(length),
		&read,
	); err != nil {
		return nil, fmt.Errorf(
			"read shared-memory section %q: %w",
			s.name,
			err,
		)
	}
	if read != uintptr(length) {
		return nil, fmt.Errorf(
			"read shared-memory section %q: read %d of %d bytes",
			s.name,
			read,
			length,
		)
	}

	return data, nil
}
