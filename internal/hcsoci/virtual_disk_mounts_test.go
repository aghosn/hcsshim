//go:build windows

package hcsoci

import (
	"encoding/json"
	"reflect"
	"testing"

	"github.com/Microsoft/hcsshim/pkg/annotations"
	specs "github.com/opencontainers/runtime-spec/specs-go"
)

func TestLCOWVirtualDiskMounts(t *testing.T) {
	mounts := []specs.Mount{
		{Type: "bind", Source: `D:\aegis\working.vhdx`, Destination: "/data", Options: []string{"rbind", "rprivate", "rw", "nodev"}},
		{Type: "bind", Source: `D:\logs`, Destination: "/logs", Options: []string{"rbind", "ro"}},
	}
	spec := &specs.Spec{Mounts: append([]specs.Mount(nil), mounts...)}
	if err := applyLCOWVirtualDiskMounts(spec); err != nil || !reflect.DeepEqual(spec.Mounts, mounts) {
		t.Fatal("ordinary CRI mounts changed without an opt-in annotation", err)
	}
	spec.Annotations = map[string]string{annotations.LCOWVirtualDiskMounts: `["/data"]`}
	if err := applyLCOWVirtualDiskMounts(spec); err != nil {
		t.Fatal(err)
	}
	if spec.Mounts[0].Type != MountTypeVirtualDisk || spec.Mounts[0].Source != mounts[0].Source ||
		!reflect.DeepEqual(spec.Mounts[0].Options, []string{"nodev"}) ||
		!reflect.DeepEqual(spec.Mounts[1], mounts[1]) {
		t.Fatalf("incorrect conversion: %+v", spec.Mounts)
	}
}

func TestLCOWVirtualDiskMountsAccessOptions(t *testing.T) {
	for _, tc := range []struct {
		name     string
		options  []string
		expected []string
	}{
		{name: "default writable", expected: []string{}},
		{name: "explicit writable", options: []string{"rbind", "rprivate", "rw"}, expected: []string{}},
		{name: "read only", options: []string{"rbind", "rprivate", "ro"}, expected: []string{"ro"}},
		{name: "read only preserved with rw", options: []string{"rw", "ro"}, expected: []string{"ro"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			spec := &specs.Spec{
				Mounts: []specs.Mount{{
					Type: "bind", Source: `D:\aegis\working.vhdx`, Destination: "/data", Options: tc.options,
				}},
				Annotations: map[string]string{annotations.LCOWVirtualDiskMounts: `["/data"]`},
			}
			if err := applyLCOWVirtualDiskMounts(spec); err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(spec.Mounts[0].Options, tc.expected) {
				t.Fatalf("mount options = %v, want %v", spec.Mounts[0].Options, tc.expected)
			}
			diskMount := spec.Mounts[0]
			containerMount := lcowVirtualDiskContainerMount(diskMount, "/run/mounts/scsi/m5")
			expectedMount := specs.Mount{
				Type: "bind", Source: "/run/mounts/scsi/m5", Destination: "/data",
				Options: append([]string{"bind"}, tc.expected...),
			}
			if !reflect.DeepEqual(containerMount, expectedMount) {
				t.Fatalf("container mount = %+v, want %+v", containerMount, expectedMount)
			}
			if !reflect.DeepEqual(diskMount.Options, tc.expected) {
				t.Fatalf("container bind flags leaked into SCSI options: %v", diskMount.Options)
			}
			data, err := json.Marshal(containerMount)
			if err != nil {
				t.Fatal(err)
			}
			t.Logf("container mount: %s", data)
		})
	}
}

func TestLCOWVirtualDiskContainerMountPreservesBindOptions(t *testing.T) {
	for _, option := range []string{"bind", "rbind"} {
		t.Run(option, func(t *testing.T) {
			mount := specs.Mount{
				Type: MountTypeVirtualDisk, Source: `D:\aegis\working.vhdx`, Destination: "/data",
				Options: []string{option, "ro", "rprivate"},
			}
			got := lcowVirtualDiskContainerMount(mount, "/run/mounts/scsi/m5")
			want := mount
			want.Type = MountTypeBind
			want.Source = "/run/mounts/scsi/m5"
			if !reflect.DeepEqual(got, want) {
				t.Fatalf("container mount = %+v, want %+v", got, want)
			}
		})
	}
}

func TestLCOWVirtualDiskMountsRejectInvalidRequests(t *testing.T) {
	for _, value := range []string{
		`invalid`, `null`, `[]`, `["/"]`, `["relative"]`, `["/data/../data"]`,
		`["/missing"]`, `["/data","/data"]`, `["/data","/missing"]`,
	} {
		t.Run(value, func(t *testing.T) {
			mount := specs.Mount{Type: "bind", Source: `D:\working.vhdx`, Destination: "/data"}
			spec := &specs.Spec{Mounts: []specs.Mount{mount},
				Annotations: map[string]string{annotations.LCOWVirtualDiskMounts: value}}
			if err := applyLCOWVirtualDiskMounts(spec); err == nil {
				t.Fatal("accepted invalid request")
			}
			if !reflect.DeepEqual(spec.Mounts[0], mount) {
				t.Fatal("failed validation partially modified the spec")
			}
		})
	}
	for _, mount := range []specs.Mount{
		{Type: "bind", Source: `relative.vhdx`, Destination: "/data"},
		{Type: "bind", Source: `D:\not-a-disk.txt`, Destination: "/data"},
		{Type: "tmpfs", Source: `D:\working.vhdx`, Destination: "/data"},
		{Type: "bind", Source: `D:\working.vhdx`, Destination: "/data", Options: []string{"unknown"}},
	} {
		spec := &specs.Spec{Mounts: []specs.Mount{mount},
			Annotations: map[string]string{annotations.LCOWVirtualDiskMounts: `["/data"]`}}
		if err := applyLCOWVirtualDiskMounts(spec); err == nil {
			t.Fatalf("accepted invalid mount %+v", mount)
		}
	}
}
