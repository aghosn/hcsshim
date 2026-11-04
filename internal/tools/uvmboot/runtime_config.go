//go:build windows

package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/pelletier/go-toml"
	"github.com/urfave/cli"
)

const siblingContainerdPipe = `\\.\pipe\vsock-sibling-containerd`

var siblingRuntimeConfigCommand = cli.Command{
	Name:  "runtime-config",
	Usage: "Prepare an isolated containerd configuration without changing the installed service",
	Flags: []cli.Flag{
		cli.StringFlag{Name: "source", Usage: "Effective configuration from containerd config dump"},
		cli.StringFlag{Name: "output", Usage: "New owned configuration file"},
		cli.StringFlag{Name: "root", Usage: "Owned runtime state directory"},
		cli.StringFlag{Name: "runtime-directory", Usage: "Directory containing the matching runhcs shim"},
	},
	Action: func(c *cli.Context) error {
		for _, name := range []string{"source", "output", "root", "runtime-directory"} {
			if !filepath.IsAbs(c.String(name)) {
				return fmt.Errorf("--%s must be an absolute path", name)
			}
		}
		if filepath.Clean(c.String("source")) == filepath.Clean(c.String("output")) {
			return errors.New("runtime configuration must not overwrite its source")
		}
		data, err := os.ReadFile(c.String("source"))
		if err != nil {
			return err
		}
		config, err := isolatedRuntimeConfig(data, c.String("root"), c.String("runtime-directory"))
		if err != nil {
			return err
		}
		file, err := os.OpenFile(c.String("output"), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
		if err != nil {
			return err
		}
		_, writeErr := file.Write(config)
		closeErr := file.Close()
		return errors.Join(writeErr, closeErr)
	},
}

func isolatedRuntimeConfig(data []byte, root, runtimeDirectory string) ([]byte, error) {
	if !filepath.IsAbs(root) || !filepath.IsAbs(runtimeDirectory) {
		return nil, errors.New("owned runtime and binary directories must be absolute")
	}
	config, err := toml.LoadBytes(data)
	if err != nil {
		return nil, fmt.Errorf("parse installed containerd configuration: %w", err)
	}
	var selected []string
	for _, plugin := range []string{"io.containerd.cri.v1.runtime", "io.containerd.grpc.v1.cri"} {
		path := []string{"plugins", plugin, "containerd", "runtimes", "runhcs-lcow"}
		if _, ok := config.GetPath(path).(*toml.Tree); ok {
			if selected != nil {
				return nil, errors.New("ambiguous LCOW runtime configuration")
			}
			selected = path
		}
	}
	if selected == nil {
		return nil, errors.New("installed containerd configuration has no runhcs-lcow CRI runtime to preserve")
	}
	original := config.GetPath(selected).(*toml.Tree)
	images, _ := config.GetPath([]string{"plugins", "io.containerd.cri.v1.images"}).(*toml.Tree)
	snapshotter, _ := original.Get("snapshotter").(string)
	if snapshotter == "" && images != nil {
		snapshotter, _ = images.GetPath([]string{"runtime_platforms", "runhcs-lcow", "snapshotter"}).(string)
	}
	if snapshotter == "" {
		snapshotter, _ = config.GetPath(append(append([]string(nil), selected[:3]...), "snapshotter")).(string)
	}
	if snapshotter == "" && images != nil {
		snapshotter, _ = images.Get("snapshotter").(string)
	}
	if snapshotter == "" {
		return nil, errors.New("installed configuration does not identify the LCOW snapshotter")
	}
	if snapshotter != "" && config.GetPath([]string{"proxy_plugins", snapshotter}) != nil {
		return nil, errors.New("LCOW uses an external snapshotter; refusing to share its snapshot state between independent containerd daemons")
	}
	runtime, err := toml.TreeFromMap(original.ToMap())
	if err != nil {
		return nil, err
	}
	runtime.Set("runtime_path", filepath.Join(runtimeDirectory, "containerd-shim-runhcs-v1.exe"))
	annotations := []string{"io.microsoft.virtualmachine.*"}
	if value := original.Get("pod_annotations"); value != nil {
		switch values := value.(type) {
		case []interface{}:
			for _, value := range values {
				name, ok := value.(string)
				if !ok {
					return nil, errors.New("LCOW pod_annotations must contain strings")
				}
				annotations = append(annotations, name)
			}
		case []string:
			annotations = append(annotations, values...)
		default:
			return nil, errors.New("LCOW pod_annotations must be an array")
		}
	}
	runtime.Set("pod_annotations", annotations)
	target := append(append([]string(nil), selected[:len(selected)-1]...), "runhcs-sibling")
	config.SetPath(target, runtime)
	config.SetPath(append(append([]string(nil), selected[:3]...), "default_runtime_name"), "runhcs-sibling")
	if images != nil {
		images.Set("snapshotter", snapshotter)
		platform, err := toml.TreeFromMap(map[string]interface{}{
			"platform": "linux/amd64", "snapshotter": snapshotter,
		})
		if err != nil {
			return nil, err
		}
		if existing, ok := images.GetPath([]string{"runtime_platforms", "runhcs-lcow"}).(*toml.Tree); ok {
			platform, err = toml.TreeFromMap(existing.ToMap())
			if err != nil {
				return nil, err
			}
			platform.Set("snapshotter", snapshotter)
		}
		images.SetPath([]string{"runtime_platforms", "runhcs-sibling"}, platform)
	} else {
		config.SetPath(append(append([]string(nil), selected[:3]...), "snapshotter"), snapshotter)
	}
	config.Set("root", filepath.Join(root, "containerd-root"))
	config.Set("state", filepath.Join(root, "containerd-state"))
	// Input is already resolved by config dump; don't reapply installed imports.
	config.Set("imports", []string{})
	config.SetPath([]string{"grpc", "address"}, siblingContainerdPipe)
	config.SetPath([]string{"grpc", "tcp_address"}, "")
	config.SetPath([]string{"debug", "address"}, "")
	config.SetPath([]string{"metrics", "address"}, "")
	config.SetPath([]string{"ttrpc", "address"}, "")
	plugin := config.GetPath(selected[:2]).(*toml.Tree)
	if plugin.Has("stream_server_port") {
		plugin.Set("stream_server_port", "0")
	}
	plugins := config.Get("plugins").(*toml.Tree)
	for _, name := range plugins.Keys() {
		if len(name) >= len("io.containerd.snapshotter.v1.") && name[:len("io.containerd.snapshotter.v1.")] == "io.containerd.snapshotter.v1." {
			if snapshotter, ok := plugins.GetPath([]string{name}).(*toml.Tree); ok && snapshotter.Has("root_path") {
				snapshotter.Set("root_path", filepath.Join(root, "snapshotters", name))
			}
		}
	}
	output, err := config.ToTomlString()
	if err != nil {
		return nil, err
	}
	return []byte(output), nil
}
