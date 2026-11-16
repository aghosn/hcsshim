//go:build windows

// Copyright (c) Microsoft Corporation. All rights reserved.

package sibling

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"time"

	"github.com/Microsoft/go-winio"
	"github.com/Microsoft/hcsshim/internal/uvm"
)

const (
	// PartitionSealFrame is distinct from terminal/container request types 0-3.
	PartitionSealFrame      = 4
	partitionSealVersion    = 1
	partitionSealReplyLimit = 8192
)

// PartitionSealResult is one owner's observation, not a seal-state inventory.
// Dispatched reports submission attempt; uncertain effects are never rolled back.
type PartitionSealResult struct {
	Version    int    `json:"version"`
	Role       string `json:"role"`
	VMID       string `json:"vm_id"`
	Mask       uint64 `json:"mask"`
	Outcome    string `json:"outcome"`
	Dispatched bool   `json:"dispatched"`
	Error      string `json:"error"`
}

// PartitionSealCallback borrows the endpoint's live VM through synchronous native
// completion and returns its actual ID even when readiness prevents dispatch.
type PartitionSealCallback func(uint64) (string, error)

// validSealRole limits control to the two existing single-instance role pipes.
func validSealRole(role string) bool { return role == "diode" || role == "workload" }

// writeSealFrame preserves attach's type/uint16-length framing for this control.
func writeSealFrame(w io.Writer, payload []byte) error {
	frame := make([]byte, 3+len(payload))
	frame[0] = PartitionSealFrame
	binary.LittleEndian.PutUint16(frame[1:], uint16(len(payload)))
	copy(frame[3:], payload)
	n, err := w.Write(frame)
	if err == nil && n != len(frame) {
		err = io.ErrShortWrite
	}
	return err
}

// RequestPartitionSeal sends one exact mask to the live role owner, without a
// retry or console. A lost/malformed reply after sending leaves effects unknown.
// There is no client completion timeout that could be mistaken for native abort.
func RequestPartitionSeal(role string, mask uint64) (*PartitionSealResult, error) {
	if !validSealRole(role) {
		return nil, errors.New("partition seal requires diode or workload")
	}
	timeout := 5 * time.Second
	conn, err := winio.DialPipe(`\\.\pipe\sibling-`+role, &timeout)
	if err != nil {
		return nil, fmt.Errorf("connect to protected %s owner: %w", role, err)
	}
	defer conn.Close()
	var request [9]byte
	request[0] = partitionSealVersion
	binary.LittleEndian.PutUint64(request[1:], mask)
	if err := writeSealFrame(conn, request[:]); err != nil {
		return nil, fmt.Errorf("seal request write failed; submission/effects unknown, do not automatically retry: %w", err)
	}
	result, err := readPartitionSealResult(conn, role, mask)
	if err != nil {
		return nil, fmt.Errorf("seal response lost or invalid; submission/effects unknown, do not automatically retry: %w", err)
	}
	if result.Outcome != "completed" {
		return result, fmt.Errorf("partition seal %s (dispatched=%t): %s", result.Outcome, result.Dispatched, result.Error)
	}
	return result, nil
}

// readPartitionSealResult accepts only a bounded, complete matching owner reply.
func readPartitionSealResult(r io.Reader, role string, mask uint64) (*PartitionSealResult, error) {
	var header [3]byte
	if _, err := io.ReadFull(r, header[:]); err != nil {
		return nil, err
	}
	length := int(binary.LittleEndian.Uint16(header[1:]))
	if header[0] != PartitionSealFrame || length == 0 || length > partitionSealReplyLimit {
		return nil, errors.New("unsupported seal reply frame")
	}
	payload := make([]byte, length)
	if _, err := io.ReadFull(r, payload); err != nil {
		return nil, err
	}
	// Require fields even for zero/false values; an old or partial peer must
	// not turn omitted evidence into an acknowledgement.
	fields := make(map[string]json.RawMessage)
	shape := json.NewDecoder(bytes.NewReader(payload))
	if token, err := shape.Token(); err != nil || token != json.Delim('{') {
		return nil, errors.New("seal reply is not an object")
	}
	for shape.More() {
		token, err := shape.Token()
		if err != nil {
			return nil, err
		}
		key, ok := token.(string)
		if !ok {
			return nil, errors.New("invalid seal reply field")
		}
		if _, exists := fields[key]; exists {
			return nil, fmt.Errorf("duplicate seal reply field %s", key)
		}
		var value json.RawMessage
		if err := shape.Decode(&value); err != nil {
			return nil, err
		}
		fields[key] = value
	}
	if _, err := shape.Token(); err != nil {
		return nil, err
	}
	if _, err := shape.Token(); !errors.Is(err, io.EOF) {
		return nil, errors.New("trailing seal reply data")
	}
	if len(fields) != 7 {
		return nil, errors.New("unexpected seal reply fields")
	}
	for _, key := range []string{"version", "role", "vm_id", "mask", "outcome", "dispatched", "error"} {
		value, ok := fields[key]
		if !ok || bytes.Equal(bytes.TrimSpace(value), []byte("null")) {
			return nil, fmt.Errorf("missing seal reply field %s", key)
		}
	}
	var result PartitionSealResult
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&result); err != nil {
		return nil, err
	}
	if result.Version != partitionSealVersion || result.Role != role || result.Mask != mask {
		return nil, errors.New("seal reply version/role/mask mismatch")
	}
	switch result.Outcome {
	case "completed":
		if !result.Dispatched || result.VMID == "" || result.Error != "" {
			return nil, errors.New("inconsistent completed seal reply")
		}
	case "rejected":
		if result.Dispatched || result.Error == "" {
			return nil, errors.New("inconsistent rejected seal reply")
		}
	case "uncertain":
		if !result.Dispatched || result.VMID == "" || result.Error == "" {
			return nil, errors.New("inconsistent uncertain seal reply")
		}
	default:
		return nil, errors.New("unknown seal outcome")
	}
	return &result, nil
}

// ServePartitionSeal validates the fixed version/uint64 request before invoking
// the role-bound owner. It neither owns a VM nor caches success. The handler must
// retain its connection and owner until this synchronous callback returns, even
// on disconnect/cancellation; failure to deliver the reply never cancels a call.
func ServePartitionSeal(conn net.Conn, role string, kind byte, payload []byte, seal PartitionSealCallback) error {
	if !validSealRole(role) || kind != PartitionSealFrame || len(payload) != 9 || payload[0] != partitionSealVersion {
		return errors.New("invalid partition seal request")
	}
	result := PartitionSealResult{Version: partitionSealVersion, Role: role,
		Mask: binary.LittleEndian.Uint64(payload[1:]), Outcome: "rejected"}
	var err error = &uvm.PartitionSealError{Err: errors.New("owner does not support protected partition sealing")}
	if seal != nil {
		result.VMID, err = seal(result.Mask)
	}
	if err == nil {
		result.Outcome, result.Dispatched = "completed", true
	} else {
		var native *uvm.PartitionSealError
		result.Dispatched = !errors.As(err, &native) || native.Dispatched
		if result.Dispatched {
			result.Outcome = "uncertain"
		}
		result.Error = err.Error()
		if len(result.Error) > 512 {
			result.Error = result.Error[:512]
		}
	}
	reply, err := json.Marshal(result)
	if err != nil {
		return err
	}
	if len(reply) > partitionSealReplyLimit {
		return errors.New("partition seal reply exceeds bound")
	}
	return writeSealFrame(conn, reply)
}
