//go:build windows

package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"

	runhcsopts "github.com/Microsoft/hcsshim/cmd/containerd-shim-runhcs-v1/options"
	"github.com/Microsoft/hcsshim/internal/hns"
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
		cli.StringFlag{Name: "image-cache-root", Usage: "Persistent owned image store; runtime state remains per session"},
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
		config, err := isolatedRuntimeConfig(data, c.String("root"), c.String("runtime-directory"), c.String("image-cache-root"))
		if err != nil {
			return err
		}
		config, err = isolatedRuntimeCNI(config, c.String("root"), hns.GetHNSNetworkByName)
		if err != nil {
			return fmt.Errorf("prepare owned CNI configuration: %w", err)
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

func isolatedRuntimeCNI(data []byte, root string, lookup func(string) (*hns.HNSNetwork, error)) ([]byte, error) {
	config, err := toml.LoadBytes(data)
	if err != nil {
		return nil, err
	}
	var path []string
	for _, plugin := range []string{"io.containerd.cri.v1.runtime", "io.containerd.grpc.v1.cri"} {
		candidate := []string{"plugins", plugin, "cni", "conf_dir"}
		if config.HasPath(candidate) {
			if path != nil {
				return nil, errors.New("ambiguous CNI configuration directories")
			}
			path = candidate
		}
	}
	if path == nil {
		return nil, errors.New("installed configuration has no CNI conf_dir")
	}
	source, ok := config.GetPath(path).(string)
	if !ok || !filepath.IsAbs(source) {
		return nil, errors.New("installed CNI conf_dir must be an absolute path")
	}
	entries, err := os.ReadDir(source)
	if err != nil {
		return nil, err
	}
	directory := filepath.Join(root, "cni-config")
	if err := os.Mkdir(directory, 0700); err != nil {
		return nil, err
	}
	count := 0
	for _, entry := range entries {
		extension := strings.ToLower(filepath.Ext(entry.Name()))
		if entry.IsDir() || (extension != ".conf" && extension != ".conflist" && extension != ".json") {
			continue
		}
		content, err := os.ReadFile(filepath.Join(source, entry.Name()))
		if err != nil {
			return nil, err
		}
		content, err = ownedNATGateway(content, lookup)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", entry.Name(), err)
		}
		if err := os.WriteFile(filepath.Join(directory, entry.Name()), content, 0600); err != nil {
			return nil, err
		}
		count++
	}
	if count == 0 {
		return nil, errors.New("installed CNI directory contains no network configurations")
	}
	config.SetPath(path, directory)
	output, err := config.ToTomlString()
	return []byte(output), err
}

func ownedNATGateway(data []byte, lookup func(string) (*hns.HNSNetwork, error)) ([]byte, error) {
	var config map[string]json.RawMessage
	if err := json.Unmarshal(data, &config); err != nil {
		return nil, err
	}
	var kind string
	if err := json.Unmarshal(config["type"], &kind); err != nil {
		// Network lists contain a plugins array rather than a top-level type.
		if _, list := config["plugins"]; list && config["type"] == nil {
			return data, nil
		}
		return nil, fmt.Errorf("read CNI plugin type: %w", err)
	}
	if !strings.EqualFold(kind, "nat") {
		return data, nil
	}
	var ipam map[string]json.RawMessage
	if value := config["ipam"]; value != nil {
		if err := json.Unmarshal(value, &ipam); err != nil {
			return nil, fmt.Errorf("read NAT IPAM configuration: %w", err)
		}
	}
	if len(ipam) != 0 {
		return data, nil
	}
	var name string
	if err := json.Unmarshal(config["name"], &name); err != nil || name == "" {
		return nil, errors.New("NAT configuration has no network name")
	}
	network, err := lookup(name)
	if err != nil {
		return nil, fmt.Errorf("query existing NAT network %q: %w", name, err)
	}
	if network == nil || !strings.EqualFold(network.Type, "nat") || len(network.Subnets) != 1 {
		return nil, fmt.Errorf("existing NAT network %q must have exactly one subnet", name)
	}
	subnet := network.Subnets[0]
	_, prefix, err := net.ParseCIDR(subnet.AddressPrefix)
	gateway := net.ParseIP(subnet.GatewayAddress)
	if err != nil || prefix.IP.To4() == nil || gateway.To4() == nil || gateway.IsUnspecified() {
		return nil, fmt.Errorf("existing NAT network %q has an invalid IPv4 subnet or gateway", name)
	}
	// The NAT plugin constructs endpoint settings from CNI before it looks up
	// the existing HNS network; a bare config therefore loses that gateway.
	config["ipam"], err = json.Marshal(map[string]interface{}{
		"subnet": subnet.AddressPrefix,
		"routes": []map[string]string{{"dst": "0.0.0.0/0", "gw": subnet.GatewayAddress}},
	})
	if err != nil {
		return nil, err
	}
	return json.MarshalIndent(config, "", "  ")
}

func isolatedRuntimeConfig(data []byte, root, runtimeDirectory, imageCacheRoot string) ([]byte, error) {
	if !filepath.IsAbs(root) || !filepath.IsAbs(runtimeDirectory) {
		return nil, errors.New("owned runtime and binary directories must be absolute")
	}
	storeRoot := root
	if imageCacheRoot != "" {
		if !filepath.IsAbs(imageCacheRoot) {
			return nil, errors.New("image cache directory must be absolute")
		}
		storeRoot = imageCacheRoot
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
	// Send owned shim logs to containerd, not an unrecorded host ETW session.
	runtime.SetPath([]string{"options", "DebugType"}, int64(runhcsopts.Options_NPIPE))
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
	config.Set("root", filepath.Join(storeRoot, "containerd-root"))
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
				snapshotter.Set("root_path", filepath.Join(storeRoot, "snapshotters", name))
			}
		}
	}
	output, err := config.ToTomlString()
	if err != nil {
		return nil, err
	}
	return []byte(output), nil
}
