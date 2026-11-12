package diodecontrol

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"os/exec"
	"strings"
	"testing"
)

func frame(operation uint16, response bool, body []byte) Frame {
	h := Header{Service: Storage, Operation: operation, Length: uint32(HeaderSize + len(body)),
		Request: 0x0807060504030201, Session: 0x1817161514131211}
	if response {
		h.Flags = Response
	}
	return Frame{Header: h, Body: body}
}

func fixtures() []Frame {
	caps := make([]byte, CapabilitiesSize)
	binary.LittleEndian.PutUint16(caps[2:], MaxExports)
	binary.LittleEndian.PutUint16(caps[4:], 1)
	binary.LittleEndian.PutUint16(caps[6:], ExportSize)
	binary.LittleEndian.PutUint32(caps[8:], StorageOperations)
	binary.LittleEndian.PutUint32(caps[12:], 512)
	query := make([]byte, QuerySize+MaxExports*ExportSize)
	binary.LittleEndian.PutUint16(query, MaxExports)
	binary.LittleEndian.PutUint16(query[2:], ExportSize)
	for i := range MaxExports {
		record := query[QuerySize+i*ExportSize:]
		if i == 0 {
			record[25] = Boot | ReadOnly
		} else {
			binary.LittleEndian.PutUint64(record, uint64(i+100))
			record[24] = byte(i)
			record[25] = Retiring
			binary.LittleEndian.PutUint16(record[22:], uint16(i))
			binary.LittleEndian.PutUint32(record[16:], uint32(i))
		}
		binary.LittleEndian.PutUint64(record[8:], 65536)
	}
	add := make([]byte, MutationSize)
	binary.LittleEndian.PutUint64(add, 0x2827262524232221)
	binary.LittleEndian.PutUint16(add[10:], 7)
	add[12], add[13] = 9, ReadOnly
	remove := append([]byte(nil), add...)
	remove[10], remove[13] = 0, 0
	quiesce := make([]byte, MutationSize)
	binary.LittleEndian.PutUint16(quiesce[10:], 7)
	initial := frame(Capabilities, false, nil)
	initial.Header.Session = 0
	pending := frame(Remove, true, nil)
	pending.Header.Status = Pending
	failure := frame(Add, true, nil)
	failure.Header.Status = Conflict
	return []Frame{
		initial, frame(Capabilities, true, caps), frame(Query, false, nil),
		frame(Query, true, query), frame(Add, false, add), frame(Add, true, nil),
		frame(Remove, false, remove), frame(Remove, true, nil), pending, failure,
		frame(Quiesce, false, quiesce), frame(Quiesce, true, nil),
	}
}

func TestWireGoldenAndRoundTrip(t *testing.T) {
	raw, err := fixtures()[0].MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	const golden = "44434d31010001000100000028000000010203040506070800000000000000000000000000000000"
	if hex.EncodeToString(raw) != golden {
		t.Fatalf("wire drift: %x", raw)
	}
	for _, f := range fixtures() {
		raw, err := f.MarshalBinary()
		if err != nil {
			t.Fatalf("marshal %d/%d: %v", f.Header.Operation, f.Header.Flags, err)
		}
		got, err := ReadFrame(bytes.NewReader(raw))
		if err != nil || got.Header != f.Header || !bytes.Equal(got.Body, f.Body) {
			t.Fatalf("round trip: %+v, %v", got, err)
		}
	}
}

func TestStreamBoundaries(t *testing.T) {
	var combined []byte
	for _, f := range fixtures() {
		raw, err := f.MarshalBinary()
		if err != nil {
			t.Fatal(err)
		}
		combined = append(combined, raw...)
		for end := 1; end < len(raw); end++ {
			if _, err := ReadFrame(bytes.NewReader(raw[:end])); err == nil {
				t.Fatalf("accepted truncation at %d/%d", end, len(raw))
			}
		}
	}
	r := bytes.NewReader(combined)
	for range fixtures() {
		if _, err := ReadFrame(oneByteReader{r}); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := ReadFrame(r); !errors.Is(err, io.EOF) {
		t.Fatalf("expected stream EOF, got %v", err)
	}
}

type oneByteReader struct{ io.Reader }

func (r oneByteReader) Read(p []byte) (int, error) {
	if len(p) > 1 {
		p = p[:1]
	}
	return r.Reader.Read(p)
}

func TestRejectedStorageRecords(t *testing.T) {
	cases := []struct {
		name   string
		index  int
		offset int
		value  byte
	}{
		{"zero-capacity-limit", 1, 2, 0},
		{"oversize-capacity-limit", 1, 2, MaxExports + 1},
		{"capabilities-reserved", 1, 16, 1},
		{"query-reserved", 3, 4, 1},
		{"duplicate-lun", 3, QuerySize + ExportSize + 24, 0},
		{"boot-token", 3, QuerySize, 1},
		{"boot-retiring", 3, QuerySize + 25, Boot | Retiring},
		{"missing-dynamic-token", 3, QuerySize + ExportSize, 0},
		{"record-reserved", 3, QuerySize + 26, 1},
		{"root-add", 4, 12, 0},
		{"invalid-lun", 4, 12, 255},
		{"invalid-add-flags", 4, 13, Retiring},
		{"mutation-reserved", 4, 14, 1},
		{"remove-backend", 6, 8, 1},
		{"quiesce-token", 10, 0, 1},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := fixtures()[tc.index]
			f.Body[tc.offset] = tc.value
			if _, err := f.MarshalBinary(); err == nil {
				t.Fatal("accepted invalid record")
			}
		})
	}
	for _, op := range []uint16{Capabilities, Query, Add} {
		f := frame(op, true, nil)
		f.Header.Status = Pending
		if _, err := f.MarshalBinary(); err == nil {
			t.Fatalf("pending is invalid for operation %d", op)
		}
	}
}

// The cross-repository gate compiles the canonical C validators with ASan/UBSan
// and supplies the executable. Ordinary host-only tests need no C compiler.
func TestCanonicalCParity(t *testing.T) {
	oracle := os.Getenv("DIODE_CONTROL_ORACLE")
	if oracle == "" {
		t.Skip("run vsock-tun-forward/test/diode-control.tests.py for C/Go parity")
	}
	var corpus [][]byte
	corpus = append(corpus, nil, make([]byte, HeaderSize), make([]byte, MaxFrame+1))
	for _, f := range fixtures() {
		raw, err := f.MarshalBinary()
		if err != nil {
			t.Fatal(err)
		}
		corpus = append(corpus, raw)
		for end := 0; end < len(raw); end++ {
			corpus = append(corpus, raw[:end])
		}
		for offset := range raw {
			for _, value := range []byte{0, 1, 0xff} {
				mutated := append([]byte(nil), raw...)
				mutated[offset] = value
				corpus = append(corpus, mutated)
			}
		}
	}
	var input strings.Builder
	for _, raw := range corpus {
		input.WriteString(hex.EncodeToString(raw))
		input.WriteByte('\n')
	}
	command := exec.Command(oracle)
	command.Stdin = strings.NewReader(input.String())
	var stderr bytes.Buffer
	command.Stderr = &stderr
	output, err := command.Output()
	if err != nil {
		t.Fatalf("C oracle: %v: %s", err, &stderr)
	}
	lines := strings.Split(strings.TrimSuffix(string(output), "\n"), "\n")
	if len(lines) != len(corpus) {
		t.Fatalf("C returned %d results for %d frames", len(lines), len(corpus))
	}
	for i, raw := range corpus {
		_, err := ReadFrame(bytes.NewReader(raw))
		valid := err == nil
		if lines[i] != "valid" && lines[i] != "invalid" {
			t.Fatalf("invalid oracle result %q", lines[i])
		}
		if valid != (lines[i] == "valid") {
			t.Fatalf("C/Go mismatch at %d: C=%s Go=%v raw=%x", i, lines[i], err, raw)
		}
	}
	t.Logf("canonical C/Go parity: %d frames", len(corpus))
}

func FuzzReadFrame(f *testing.F) {
	for _, fixture := range fixtures() {
		raw, err := fixture.MarshalBinary()
		if err != nil {
			f.Fatal(err)
		}
		f.Add(raw)
	}
	f.Fuzz(func(t *testing.T, raw []byte) {
		got, err := ReadFrame(bytes.NewReader(raw))
		if err != nil {
			return
		}
		encoded, err := got.MarshalBinary()
		if err != nil || !bytes.Equal(encoded, raw[:len(encoded)]) {
			t.Fatalf("accepted frame cannot round trip: %v", err)
		}
	})
}
