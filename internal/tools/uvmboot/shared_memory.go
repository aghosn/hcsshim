//go:build windows

package main

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"fmt"

	"github.com/Microsoft/hcsshim/internal/sibling"
)

type sharedMemorySection struct {
	*sibling.Section
	name    string
	hcsName string
	size    uint64
}

func createSharedMemorySection(name string, size uint64) (*sharedMemorySection, error) {
	section, err := sibling.CreateSection(name, size)
	if err != nil {
		return nil, err
	}
	return &sharedMemorySection{section, section.Name, section.HCSName, section.Size}, nil
}

func sharedMemorySectionNames(name string, sessionID uint32) (string, string, error) {
	return sibling.SectionNames(name, sessionID)
}

func (s *sharedMemorySection) Close() error {
	if s == nil {
		return nil
	}
	return s.Section.Close()
}

func (s *sharedMemorySection) write(offset uint64, data []byte) error {
	return s.Write(offset, data)
}

func (s *sharedMemorySection) read(offset, length uint64) ([]byte, error) {
	return s.Read(offset, length)
}

func (s *sharedMemorySection) hexPrefix(length uint64) (string, error) {
	data, err := s.read(0, length)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(data), nil
}

// printCrashLogs prints the bounded sibling_bus crash-log area.
func (s *sharedMemorySection) printCrashLogs() {
	const (
		offset = 0xa000
		stride = 0x3000
		header = 16
	)
	for role, name := range []string{"workload", "diode"} {
		base := uint64(offset + role*stride)
		hdr, err := s.read(base, header)
		if err != nil || !bytes.Equal(hdr[:8], []byte("SBCRASH\x00")) {
			continue
		}
		reason := binary.LittleEndian.Uint32(hdr[8:])
		length := uint64(binary.LittleEndian.Uint32(hdr[12:]))
		if length > stride-header {
			length = stride - header
		}
		text, err := s.read(base+header, length)
		if err != nil {
			continue
		}
		fmt.Printf("=== %s guest crash log (kmsg_dump reason %d) ===\n%s=== end %s guest crash log ===\n",
			name, reason, text, name)
	}
}

func (s *sharedMemorySection) expect(offset uint64, expected []byte) error {
	actual, err := s.read(offset, uint64(len(expected)))
	if err != nil {
		return err
	}
	if !bytes.Equal(actual, expected) {
		return fmt.Errorf("shared-memory marker mismatch at offset %d: got %x, expected %x", offset, actual, expected)
	}
	return nil
}
