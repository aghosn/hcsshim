//go:build windows

// Copyright (c) Microsoft Corporation. All rights reserved.

package uvm

import (
	"encoding/json"
	"io"
	"math"
	"strconv"
	"strings"
	"testing"
)

// TestProtectedSharedPartitionSealPayload exercises the real API's encoder with
// zero, known, future and full-width bitmaps. Exactly one explicit numeric
// SealFlags field must retain every bit without float64 conversion or defaults,
// protecting extensible forwarding rather than simulating HV validation.
func TestProtectedSharedPartitionSealPayload(t *testing.T) {
	for _, flags := range []uint64{0, 1, 2, 3, 1 << 8, 1 << 63, math.MaxUint64} {
		t.Run(strconv.FormatUint(flags, 10), func(t *testing.T) {
			payload, err := partitionSealPayload(flags)
			if err != nil {
				t.Fatal(err)
			}
			decoder := json.NewDecoder(strings.NewReader(payload))
			decoder.UseNumber()
			if token, err := decoder.Token(); err != nil || token != json.Delim('{') {
				t.Fatalf("expected JSON object: %v, %v", token, err)
			}
			if token, err := decoder.Token(); err != nil || token != "SealFlags" {
				t.Fatalf("expected explicit SealFlags field: %v, %v", token, err)
			}
			token, err := decoder.Token()
			number, ok := token.(json.Number)
			if err != nil || !ok {
				t.Fatalf("expected numeric SealFlags: %v, %v", token, err)
			}
			got, err := strconv.ParseUint(number.String(), 10, 64)
			if err != nil || got != flags {
				t.Fatalf("SealFlags=%s error=%v, want %d", number, err, flags)
			}
			if decoder.More() {
				t.Fatal("payload contains extra or duplicate fields")
			}
			if token, err := decoder.Token(); err != nil || token != json.Delim('}') {
				t.Fatalf("expected object end: %v, %v", token, err)
			}
			if _, err := decoder.Token(); err != io.EOF {
				t.Fatalf("unexpected trailing payload: %v", err)
			}
		})
	}
}
