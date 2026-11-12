// Package diodecontrol defines the bounded native diode management protocol.
// The canonical C contract is diagnostics/sibling-bus/diode_control.h in
// vsock-tun-forward. Session and ownership tokens are not authentication.
package diodecontrol

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

const (
	Port             uint32 = 0x50000001
	Magic            uint32 = 0x314d4344
	Version          uint16 = 1
	HeaderSize              = 40
	MaxExports              = 64
	ExportSize              = 32
	CapabilitiesSize        = 24
	MutationSize            = 16
	QuerySize               = 8
	MaxFrame                = HeaderSize + QuerySize + MaxExports*ExportSize

	Response uint16 = 1
	Storage  uint16 = 1

	Capabilities uint16 = 1
	Query        uint16 = 2
	Add          uint16 = 3
	Remove       uint16 = 4
	Quiesce      uint16 = 5

	StorageOperations uint32 = 0x1f

	OK          uint32 = 0
	Pending     uint32 = 1
	Invalid     uint32 = 2
	Unsupported uint32 = 3
	Conflict    uint32 = 4
	NotFound    uint32 = 5
	Busy        uint32 = 6
	IOError     uint32 = 7
	Stale       uint32 = 8

	ReadOnly byte = 1
	Retiring byte = 2
	Boot     byte = 4
)

var errInvalidFrame = errors.New("invalid diode control frame")

type Header struct {
	Service   uint16
	Operation uint16
	Flags     uint16
	Length    uint32
	Request   uint64
	Session   uint64
	Status    uint32
}

func (h Header) valid() bool {
	return h.Service != 0 && h.Operation != 0 && h.Request != 0 &&
		h.Flags <= Response && h.Length >= HeaderSize && h.Length <= MaxFrame &&
		h.Status <= Stale && (h.Flags != 0 || h.Status == 0) &&
		(h.Session != 0 || (h.Flags == 0 && h.Service == Storage && h.Operation == Capabilities))
}

func (h Header) MarshalBinary() ([]byte, error) {
	if !h.valid() {
		return nil, errInvalidFrame
	}
	p := make([]byte, HeaderSize)
	binary.LittleEndian.PutUint32(p, Magic)
	binary.LittleEndian.PutUint16(p[4:], Version)
	binary.LittleEndian.PutUint16(p[6:], h.Service)
	binary.LittleEndian.PutUint16(p[8:], h.Operation)
	binary.LittleEndian.PutUint16(p[10:], h.Flags)
	binary.LittleEndian.PutUint32(p[12:], h.Length)
	binary.LittleEndian.PutUint64(p[16:], h.Request)
	binary.LittleEndian.PutUint64(p[24:], h.Session)
	binary.LittleEndian.PutUint32(p[32:], h.Status)
	return p, nil
}

func ParseHeader(p []byte) (Header, error) {
	if len(p) != HeaderSize || binary.LittleEndian.Uint32(p) != Magic ||
		binary.LittleEndian.Uint16(p[4:]) != Version || binary.LittleEndian.Uint32(p[36:]) != 0 {
		return Header{}, errInvalidFrame
	}
	h := Header{
		Service:   binary.LittleEndian.Uint16(p[6:]),
		Operation: binary.LittleEndian.Uint16(p[8:]),
		Flags:     binary.LittleEndian.Uint16(p[10:]),
		Length:    binary.LittleEndian.Uint32(p[12:]),
		Request:   binary.LittleEndian.Uint64(p[16:]),
		Session:   binary.LittleEndian.Uint64(p[24:]),
		Status:    binary.LittleEndian.Uint32(p[32:]),
	}
	if !h.valid() {
		return Header{}, errInvalidFrame
	}
	return h, nil
}

// ValidateStorage validates one complete body, including reserved fields and
// duplicate export identities. It does not establish backend state or ownership.
func ValidateStorage(h Header, p []byte) error {
	if !h.valid() || h.Service != Storage || h.Operation > Quiesce ||
		len(p) != int(h.Length)-HeaderSize || !validStorageBody(h, p) {
		return errInvalidFrame
	}
	return nil
}

func validStorageBody(h Header, p []byte) bool {
	if h.Flags != 0 && h.Status != OK {
		return len(p) == 0 && (h.Status != Pending || h.Operation == Remove || h.Operation == Quiesce)
	}
	if h.Flags == 0 && h.Operation <= Query {
		return len(p) == 0
	}
	if h.Flags != 0 && h.Operation == Capabilities {
		return len(p) == CapabilitiesSize &&
			binary.LittleEndian.Uint16(p[2:]) > 0 &&
			binary.LittleEndian.Uint16(p[2:]) <= MaxExports &&
			binary.LittleEndian.Uint16(p[4:]) <= binary.LittleEndian.Uint16(p[2:]) &&
			binary.LittleEndian.Uint16(p[6:]) == ExportSize &&
			binary.LittleEndian.Uint32(p[8:]) & ^StorageOperations == 0 &&
			binary.LittleEndian.Uint32(p[12:]) == 512 &&
			binary.LittleEndian.Uint64(p[16:]) == 0
	}
	if h.Flags != 0 && h.Operation == Query {
		if len(p) < QuerySize || binary.LittleEndian.Uint16(p[2:]) != ExportSize ||
			binary.LittleEndian.Uint32(p[4:]) != 0 {
			return false
		}
		count := int(binary.LittleEndian.Uint16(p))
		if count > MaxExports || len(p) != QuerySize+count*ExportSize {
			return false
		}
		p = p[QuerySize:]
		for i := range count {
			record := p[i*ExportSize : (i+1)*ExportSize]
			token := binary.LittleEndian.Uint64(record)
			lun, flags := record[24], record[25]
			if lun == 255 || flags > ReadOnly|Retiring|Boot ||
				binary.LittleEndian.Uint64(record[8:]) == 0 ||
				binary.LittleEndian.Uint32(record[26:]) != 0 ||
				binary.LittleEndian.Uint16(record[30:]) != 0 ||
				(token != 0) == (flags&Boot != 0) ||
				(lun == 0 && flags&Boot == 0) || flags&(Boot|Retiring) == Boot|Retiring {
				return false
			}
			for j := range i {
				prior := p[j*ExportSize : (j+1)*ExportSize]
				if prior[24] == lun || (token != 0 && binary.LittleEndian.Uint64(prior) == token) {
					return false
				}
			}
		}
		return true
	}
	if h.Flags != 0 {
		return len(p) == 0
	}
	if len(p) != MutationSize || binary.LittleEndian.Uint16(p[14:]) != 0 {
		return false
	}
	token := binary.LittleEndian.Uint64(p)
	lun, flags := p[12], p[13]
	if h.Operation == Quiesce {
		return token == 0 && lun == 0 && flags == 0
	}
	if token == 0 || lun == 0 || lun == 255 {
		return false
	}
	if h.Operation == Remove {
		return binary.LittleEndian.Uint32(p[8:]) == 0 && flags == 0
	}
	return flags <= ReadOnly
}

type Frame struct {
	Header Header
	Body   []byte
}

func (f Frame) MarshalBinary() ([]byte, error) {
	if err := ValidateStorage(f.Header, f.Body); err != nil {
		return nil, err
	}
	p, err := f.Header.MarshalBinary()
	if err != nil {
		return nil, err
	}
	return append(p, f.Body...), nil
}

// ReadFrame bounds allocation before reading a body. The caller must terminate
// the session after any framing error; resynchronization/replay is not supported.
func ReadFrame(r io.Reader) (Frame, error) {
	var raw [HeaderSize]byte
	if _, err := io.ReadFull(r, raw[:]); err != nil {
		return Frame{}, fmt.Errorf("read diode control header: %w", err)
	}
	h, err := ParseHeader(raw[:])
	if err != nil {
		return Frame{}, err
	}
	body := make([]byte, int(h.Length)-HeaderSize)
	if _, err := io.ReadFull(r, body); err != nil {
		return Frame{}, fmt.Errorf("read diode control body: %w", err)
	}
	if err := ValidateStorage(h, body); err != nil {
		return Frame{}, err
	}
	return Frame{Header: h, Body: body}, nil
}
