//go:build windows

package uvm

import (
	"context"
	"strings"
	"testing"
)

// Unit tests for negative testing of input to uvm.Create()

func TestCreateBadBootFilesPath(t *testing.T) {
	ctx := context.Background()
	opts := NewDefaultOptionsLCOW(t.Name(), "")
	opts.UpdateBootFilesPath(ctx, `c:\does\not\exist\I\hope`)

	_, err := CreateLCOW(ctx, opts)
	if err == nil || err.Error() != `kernel: 'c:\does\not\exist\I\hope\kernel' not found` {
		t.Fatal(err)
	}
}

func TestConfidentialVMGSFileName(t *testing.T) {
	for _, tc := range []struct {
		isolationType string
		want          string
	}{
		{"SecureNestedPaging", "cwcow.snp.vmgs"},
		{"VirtualizationBasedSecurity", "cwcow.vbs.vmgs"},
		{"GuestStateOnly", "cwcow.gso.vmgs"},
		{"", "cwcow.snp.vmgs"},              // unknown defaults to SNP
		{"SomethingElse", "cwcow.snp.vmgs"}, // unknown defaults to SNP
	} {
		if got := ConfidentialVMGSFileName(tc.isolationType); got != tc.want {
			t.Errorf("ConfidentialVMGSFileName(%q) = %q, want %q", tc.isolationType, got, tc.want)
		}
	}
}

func TestVerifyLCOWSharedMemoryRegions(t *testing.T) {
	tests := []struct {
		name   string
		region LCOWSharedMemoryRegion
		want   string
	}{
		{
			name:   "empty section name",
			region: LCOWSharedMemoryRegion{Length: 4096},
			want:   "empty section name",
		},
		{
			name: "negative offset",
			region: LCOWSharedMemoryRegion{
				SectionName: `\Sessions\3\BaseNamedObjects\test`,
				StartOffset: -4096,
				Length:      4096,
			},
			want: "negative start offset",
		},
		{
			name: "zero length",
			region: LCOWSharedMemoryRegion{
				SectionName: `\Sessions\3\BaseNamedObjects\test`,
			},
			want: "length must be greater than zero",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			opts := NewDefaultOptionsLCOW(t.Name(), "")
			opts.SharedMemoryRegions = []LCOWSharedMemoryRegion{tc.region}

			err := VerifyOptions(context.Background(), opts)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("VerifyOptions() error = %v, want error containing %q", err, tc.want)
			}
		})
	}
}
