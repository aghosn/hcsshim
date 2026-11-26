//go:build windows

package hcsoci

import (
	"encoding/json"
	"fmt"
	"path"
	"path/filepath"
	"strings"

	"github.com/Microsoft/hcsshim/pkg/annotations"
	specs "github.com/opencontainers/runtime-spec/specs-go"
)

func applyLCOWVirtualDiskMounts(spec *specs.Spec) error {
	value, present := spec.Annotations[annotations.LCOWVirtualDiskMounts]
	if !present {
		return nil
	}

	var destinations []string
	if err := json.Unmarshal([]byte(value), &destinations); err != nil || len(destinations) == 0 {
		return fmt.Errorf("%s must be a nonempty JSON array of mount destinations", annotations.LCOWVirtualDiskMounts)
	}
	converted := make(map[int][]string, len(destinations))
	for _, destination := range destinations {
		if !path.IsAbs(destination) || path.Clean(destination) != destination || destination == "/" {
			return fmt.Errorf("invalid virtual disk mount destination %q", destination)
		}
		index := -1
		for i, mount := range spec.Mounts {
			if mount.Destination == destination {
				if index != -1 {
					return fmt.Errorf("duplicate mount destination %q", destination)
				}
				index = i
			}
		}
		if index == -1 {
			return fmt.Errorf("virtual disk destination %q has no matching mount", destination)
		}
		if _, duplicate := converted[index]; duplicate {
			return fmt.Errorf("duplicate virtual disk destination %q", destination)
		}
		mount := spec.Mounts[index]
		extension := strings.ToLower(filepath.Ext(mount.Source))
		if mount.Type != MountTypeBind || !filepath.IsAbs(mount.Source) ||
			(extension != ".vhd" && extension != ".vhdx") {
			return fmt.Errorf("virtual disk destination %q requires a bind mount of an absolute VHD/VHDX path", destination)
		}
		options := []string{}
		for _, option := range mount.Options {
			switch option {
			case "bind", "rbind", "private", "rprivate", "shared", "rshared", "slave", "rslave":
				// CRI bind propagation flags are not filesystem mount options.
			case "rw":
				// Writable is the default; confidential guests reject an explicit rw option.
			case "ro", "nosuid", "nodev", "noexec", "relatime", "strictatime", "noatime", "nodiratime":
				options = append(options, option)
			default:
				return fmt.Errorf("unsupported virtual disk mount option %q for %q", option, destination)
			}
		}
		converted[index] = options
	}
	for index, options := range converted {
		spec.Mounts[index].Type = MountTypeVirtualDisk
		spec.Mounts[index].Options = options
	}
	return nil
}

func lcowVirtualDiskContainerMount(mount specs.Mount, guestPath string) specs.Mount {
	mount.Type = MountTypeBind
	mount.Source = guestPath
	for _, option := range mount.Options {
		if option == "bind" || option == "rbind" {
			return mount
		}
	}
	// The disk is already mounted in the VM. Bind that directory into the container,
	// without adding container bind flags to the SCSI mount's shared options slice.
	mount.Options = append([]string{"bind"}, mount.Options...)
	return mount
}
