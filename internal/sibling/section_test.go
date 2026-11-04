//go:build windows

package sibling

import (
	"bytes"
	"testing"

	"github.com/Microsoft/go-winio/pkg/guid"
)

func TestSectionLifetimeBoundsAndExclusiveOwnership(t *testing.T) {
	id, err := guid.NewV4()
	if err != nil {
		t.Fatal(err)
	}
	name := "hcsshim-sibling-test-" + id.String()
	section, err := CreateSection(name, 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	defer section.Close()
	seed := []byte("HCSHMEM1-HOST-SEED")
	got, err := section.Read(0, uint64(len(seed)))
	if err != nil || !bytes.Equal(got, seed) {
		t.Fatalf("shared startup seed=%q error=%v", got, err)
	}
	if other, err := CreateSection(name, 1<<20); err == nil {
		other.Close()
		t.Fatal("borrowed an already-owned shared section")
	}
	if err := section.Write(section.Size-1, []byte{1, 2}); err == nil {
		t.Fatal("allowed out-of-bounds shared write")
	}
	if _, err := section.Read(section.Size, 1); err == nil {
		t.Fatal("allowed out-of-bounds shared read")
	}
	if err := section.Close(); err != nil {
		t.Fatal(err)
	}
	if err := section.Close(); err != nil {
		t.Fatalf("close is not idempotent: %v", err)
	}
	if _, err := section.Read(0, 1); err == nil {
		t.Fatal("read an unmapped section")
	}
}
