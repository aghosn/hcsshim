// Package timesync validates and frames the native IC timesync byte stream.
package timesync

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

const (
	// HeaderSize is the size of the native IC header, excluding the pipe header.
	HeaderSize = 20
	// MaxRecordSize leaves room for the pipe header in the 4 KiB guest buffer.
	MaxRecordSize = 4088
)

// Direction identifies the expected IC transaction flags.
type Direction uint8

const (
	// Request travels from the native producer to the workload.
	Request Direction = iota
	// Response travels from the workload to the native producer.
	Response
)

// RecordSize returns the complete record size from a native IC header.
func RecordSize(header []byte) (int, error) {
	if len(header) < HeaderSize {
		return 0, errors.New("timesync: incomplete IC header")
	}
	size := HeaderSize + int(binary.LittleEndian.Uint16(header[10:12]))
	if size > MaxRecordSize {
		return 0, fmt.Errorf("timesync: record size %d exceeds limit", size)
	}
	return size, nil
}

// Validate checks a complete record without changing its declared body or IDs.
// Negotiation failure is a valid response even when it selects no versions.
func Validate(record []byte, direction Direction) error {
	size, err := RecordSize(record)
	if err != nil {
		return err
	}
	if size != len(record) {
		return errors.New("timesync: IC record length mismatch")
	}
	flags := byte(3)
	if direction == Response {
		flags = 5
	} else if direction != Request {
		return errors.New("timesync: invalid direction")
	}
	if record[17] != flags {
		return fmt.Errorf("timesync: invalid IC flags %#x", record[17])
	}
	status := binary.LittleEndian.Uint32(record[12:16])
	if status != 0 && status&0x80000000 == 0 {
		return fmt.Errorf("timesync: invalid IC status %#x", status)
	}
	body := record[HeaderSize:]
	frameMajor := binary.LittleEndian.Uint16(record[0:2])
	frameMinor := binary.LittleEndian.Uint16(record[2:4])
	kind := binary.LittleEndian.Uint16(record[4:6])
	msgMajor := binary.LittleEndian.Uint16(record[6:8])
	msgMinor := binary.LittleEndian.Uint16(record[8:10])
	switch kind {
	case 0:
		if frameMajor != 0 || frameMinor != 0 || msgMajor != 0 || msgMinor != 0 {
			return errors.New("timesync: invalid negotiation header")
		}
		if direction == Response && status != 0 && len(body) == 0 {
			return nil
		}
		if len(body) < 8 {
			return errors.New("timesync: invalid negotiation header or body")
		}
		frames := int(binary.LittleEndian.Uint16(body[0:2]))
		messages := int(binary.LittleEndian.Uint16(body[2:4]))
		if frames > 100 || messages > 100 || 8+4*(frames+messages) > len(body) {
			return errors.New("timesync: invalid negotiation version counts")
		}
		if direction == Request && (frames == 0 || messages == 0) {
			return errors.New("timesync: empty negotiation request")
		}
		if direction == Response && !((frames == 0 && messages == 0) || (frames == 1 && messages == 1)) {
			return errors.New("timesync: invalid negotiation response counts")
		}
	case 4:
		if (frameMajor != 1 && frameMajor != 3) || frameMinor != 0 || msgMinor != 0 {
			return errors.New("timesync: unsupported framework version")
		}
		if direction == Response && status != 0 && len(body) == 0 &&
			(msgMajor == 1 || msgMajor == 3 || msgMajor == 4) {
			return nil
		}
		switch msgMajor {
		case 1, 3:
			if len(body) != 28 {
				return errors.New("timesync: invalid native legacy body size")
			}
		case 4:
			if len(body) != 24 {
				return errors.New("timesync: invalid native reference body size")
			}
		default:
			return errors.New("timesync: unsupported message version")
		}
	default:
		return fmt.Errorf("timesync: unsupported IC message type %d", kind)
	}
	return nil
}

// ReadRecord reassembles one record from a byte stream and validates it.
func ReadRecord(r io.Reader, direction Direction) ([]byte, error) {
	header := make([]byte, HeaderSize)
	if _, err := io.ReadFull(r, header); err != nil {
		return nil, err
	}
	size, err := RecordSize(header)
	if err != nil {
		return nil, err
	}
	record := make([]byte, size)
	copy(record, header)
	if _, err := io.ReadFull(r, record[HeaderSize:]); err != nil {
		return nil, err
	}
	if err := Validate(record, direction); err != nil {
		return nil, err
	}
	return record, nil
}

// WriteRecord writes a validated complete record in one message-pipe write.
// A short write is an error: retrying it would create another pipe message.
func WriteRecord(w io.Writer, record []byte, direction Direction) error {
	if err := Validate(record, direction); err != nil {
		return err
	}
	n, err := w.Write(record)
	if err != nil {
		return err
	}
	if n != len(record) {
		return io.ErrShortWrite
	}
	return nil
}
