//go:build windows

package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/Microsoft/hcsshim/internal/hns"
	"github.com/pelletier/go-toml"
	"github.com/urfave/cli"
)

func TestOwnedCNIIsAppliedByRuntimeConfigCommand(t *testing.T) {
	fixture := t.TempDir()
	source, root := filepath.Join(fixture, "installed-cni"), filepath.Join(fixture, "owned")
	for _, directory := range []string{source, root} {
		if err := os.Mkdir(directory, 0700); err != nil {
			t.Fatal(err)
		}
	}
	input := []byte(`{"name":"fixture-nat","type":"nat","ipam":{"subnet":"172.28.128.0/20","routes":[{"dst":"0.0.0.0/0","gw":"172.28.128.1"}]}}`)
	if err := os.WriteFile(filepath.Join(source, "cni.conf"), input, 0600); err != nil {
		t.Fatal(err)
	}
	configuration := fmt.Sprintf(`[plugins."io.containerd.grpc.v1.cri".containerd.runtimes.runhcs-lcow]
runtime_type="io.containerd.runhcs.v1"
snapshotter="windows-lcow"
[plugins."io.containerd.grpc.v1.cri".cni]
conf_dir=%q
`, source)
	sourceConfig, output := filepath.Join(fixture, "source.toml"), filepath.Join(root, "containerd.toml")
	if err := os.WriteFile(sourceConfig, []byte(configuration), 0600); err != nil {
		t.Fatal(err)
	}
	app := cli.NewApp()
	app.Commands = []cli.Command{siblingRuntimeConfigCommand}
	cache := filepath.Join(fixture, "image-cache")
	if err := app.Run([]string{"uvmboot", "runtime-config", "--source", sourceConfig,
		"--output", output, "--root", root, "--runtime-directory", fixture,
		"--image-cache-root", cache}); err != nil {
		t.Fatal(err)
	}
	config, err := toml.LoadFile(output)
	if err != nil {
		t.Fatal(err)
	}
	if config.Get("root") != filepath.Join(cache, "containerd-root") ||
		config.Get("state") != filepath.Join(root, "containerd-state") {
		t.Fatal("persistent images and per-session runtime state were not separated")
	}
	directory := filepath.Join(root, "cni-config")
	if config.GetPath([]string{"plugins", "io.containerd.grpc.v1.cri", "cni", "conf_dir"}) != directory {
		t.Fatal("runtime-config command did not select its private CNI configuration")
	}
	if config.GetPath([]string{"plugins", "io.containerd.grpc.v1.cri", "containerd", "runtimes", "runhcs-sibling", "options", "DebugType"}) != int64(0) {
		t.Fatal("owned shim logs would still be lost to ETW")
	}
	for _, file := range []string{filepath.Join(source, "cni.conf"), filepath.Join(directory, "cni.conf")} {
		actual, err := os.ReadFile(file)
		if err != nil || !bytes.Equal(actual, input) {
			t.Fatalf("changed configured NAT settings in %s: %v", file, err)
		}
	}
}

func TestOwnedCNIProvidesExistingNATGatewayWithoutChangingInstalledConfig(t *testing.T) {
	for _, plugin := range []string{"io.containerd.cri.v1.runtime", "io.containerd.grpc.v1.cri"} {
		t.Run(plugin, func(t *testing.T) {
			source, root := t.TempDir(), t.TempDir()
			input := []byte(`{"cniVersion":"0.2.0","name":"fixture-nat","type":"nat","master":"Ethernet","capabilities":{"dns":true,"portMappings":true}}`)
			sourceFile := filepath.Join(source, "cni.conf")
			if err := os.WriteFile(sourceFile, input, 0600); err != nil {
				t.Fatal(err)
			}
			configuration := []byte(fmt.Sprintf("[plugins.%q.cni]\nconf_dir=%q\nbin_dir='C:\\installed\\cni'\n", plugin, source))
			calls := 0
			output, err := isolatedRuntimeCNI(configuration, root, func(name string) (*hns.HNSNetwork, error) {
				calls++
				if name != "fixture-nat" {
					t.Fatalf("queried a different network: %s", name)
				}
				return &hns.HNSNetwork{Type: "NAT", Subnets: []hns.Subnet{{
					AddressPrefix: "172.28.128.0/20", GatewayAddress: "172.28.128.1",
				}}}, nil
			})
			if err != nil {
				t.Fatal(err)
			}
			config, err := toml.LoadBytes(output)
			if err != nil {
				t.Fatal(err)
			}
			directory := filepath.Join(root, "cni-config")
			if config.GetPath([]string{"plugins", plugin, "cni", "conf_dir"}) != directory ||
				config.GetPath([]string{"plugins", plugin, "cni", "bin_dir"}) != `C:\installed\cni` || calls != 1 {
				t.Fatal("owned daemon did not use private CNI configuration and installed plugins")
			}
			original, err := os.ReadFile(sourceFile)
			if err != nil || !bytes.Equal(original, input) {
				t.Fatal("changed the installed CNI configuration", err)
			}
			content, err := os.ReadFile(filepath.Join(directory, "cni.conf"))
			if err != nil {
				t.Fatal(err)
			}
			var actual struct {
				Name, Type, Master string
				Capabilities       map[string]bool
				IPAM               struct {
					Type, Subnet string
					Routes       []struct{ Dst, GW string }
				}
			}
			if err := json.Unmarshal(content, &actual); err != nil {
				t.Fatal(err)
			}
			if actual.Name != "fixture-nat" || actual.Type != "nat" || actual.Master != "Ethernet" ||
				!actual.Capabilities["dns"] || !actual.Capabilities["portMappings"] ||
				actual.IPAM.Type != "" || actual.IPAM.Subnet != "172.28.128.0/20" ||
				len(actual.IPAM.Routes) != 1 || actual.IPAM.Routes[0].Dst != "0.0.0.0/0" ||
				actual.IPAM.Routes[0].GW != "172.28.128.1" {
				t.Fatalf("NAT endpoint would lose its gateway or original options: %+v", actual)
			}
		})
	}
}

func TestOwnedCNILeavesConfiguredIPAMAndOtherPluginsUnchanged(t *testing.T) {
	for _, input := range []string{
		`{"name":"fixture","type":"nat","ipam":{"type":"custom"}}`,
		`{"name":"fixture","type":"nat","ipam":{"subnet":"10.0.0.0/24"}}`,
		`{"name":"fixture","type":"sdnbridge"}`,
		`{"name":"fixture","plugins":[{"type":"sdnbridge"}]}`,
	} {
		output, err := ownedNATGateway([]byte(input), func(string) (*hns.HNSNetwork, error) {
			t.Fatal("queried HNS for an already configured or non-NAT plugin")
			return nil, nil
		})
		if err != nil || string(output) != input {
			t.Fatalf("changed existing CNI behavior: %s: %v", output, err)
		}
	}
}

func TestOwnedCNIRejectsMissingOrInvalidNATGateway(t *testing.T) {
	for _, network := range []*hns.HNSNetwork{
		nil,
		{Type: "NAT"},
		{Type: "NAT", Subnets: []hns.Subnet{{AddressPrefix: "172.28.128.0/20"}}},
		{Type: "NAT", Subnets: []hns.Subnet{{AddressPrefix: "invalid", GatewayAddress: "172.28.128.1"}}},
		{Type: "NAT", Subnets: []hns.Subnet{{AddressPrefix: "172.28.128.0/20", GatewayAddress: "0.0.0.0"}}},
	} {
		if _, err := ownedNATGateway([]byte(`{"name":"fixture","type":"nat"}`),
			func(string) (*hns.HNSNetwork, error) { return network, nil }); err == nil {
			t.Fatalf("accepted invalid NAT network: %+v", network)
		}
	}
	failure := errors.New("network query failed")
	_, err := ownedNATGateway([]byte(`{"name":"fixture","type":"nat"}`),
		func(string) (*hns.HNSNetwork, error) { return nil, failure })
	if !errors.Is(err, failure) {
		t.Fatalf("lost network query failure: %v", err)
	}
}

func TestIsolatedRuntimePreservesInstalledOptionsAndOriginalHandler(t *testing.T) {
	for _, plugin := range []string{"io.containerd.cri.v1.runtime", "io.containerd.grpc.v1.cri"} {
		t.Run(plugin, func(t *testing.T) {
			input := `version=3
root='C:\installed'
imports=['C:\installed\extra.toml']
[grpc]
address='\\.\pipe\installed'
tcp_address='127.0.0.1:1234'
[debug]
address='\\.\pipe\installed-debug'
[metrics]
address='127.0.0.1:1338'
[plugins."io.containerd.snapshotter.v1.windows-lcow"]
root_path='C:\installed\snapshots'
[plugins."io.containerd.cri.v1.images"]
snapshotter='windows'
[plugins."io.containerd.cri.v1.images".runtime_platforms.runhcs-lcow]
platform='linux/amd64'
snapshotter='windows-lcow'
[plugins."` + plugin + `"]
stream_server_port='12345'
[plugins."` + plugin + `".containerd.runtimes.runhcs-lcow]
runtime_type='io.containerd.runhcs.v1'
snapshotter='windows-lcow'
pod_annotations=['existing.*']
[plugins."` + plugin + `".containerd.runtimes.runhcs-lcow.options]
SandboxIsolation=1
LCOWSecurityPolicyEnabled=true
LCOWRequireLayerIntegrity=true
DebugType=2
`
			data, err := isolatedRuntimeConfig([]byte(input), `C:\owned`, `C:\runtime`, "")
			if err != nil {
				t.Fatal(err)
			}
			original, _ := toml.Load(input)
			config, err := toml.LoadBytes(data)
			if err != nil {
				t.Fatal(err)
			}
			path := []string{"plugins", plugin, "containerd", "runtimes"}
			old := append(append([]string{}, path...), "runhcs-lcow")
			child := append(append([]string{}, path...), "runhcs-sibling")
			if !reflect.DeepEqual(config.GetPath(old).(*toml.Tree).ToMap(), original.GetPath(old).(*toml.Tree).ToMap()) {
				t.Fatal("changed the original runtime handler")
			}
			options := append(append([]string{}, child...), "options")
			originalOptions := append(append([]string{}, old...), "options")
			expectedOptions := original.GetPath(originalOptions).(*toml.Tree).ToMap()
			expectedOptions["DebugType"] = int64(0)
			if !reflect.DeepEqual(config.GetPath(options).(*toml.Tree).ToMap(), expectedOptions) {
				t.Fatal("changed security, isolation or layer-integrity options")
			}
			if config.GetPath(append(child, "runtime_path")) != `C:\runtime\containerd-shim-runhcs-v1.exe` ||
				config.GetPath([]string{"grpc", "address"}) != siblingContainerdPipe ||
				config.Get("root") != `C:\owned\containerd-root` || config.Get("state") != `C:\owned\containerd-state` ||
				config.GetPath([]string{"metrics", "address"}) != "" || config.GetPath([]string{"grpc", "tcp_address"}) != "" ||
				config.GetPath([]string{"plugins", "io.containerd.snapshotter.v1.windows-lcow", "root_path"}) != `C:\owned\snapshotters\io.containerd.snapshotter.v1.windows-lcow` {
				t.Fatal("runtime was not isolated from the installed daemon")
			}
			if !strings.Contains(string(data), "existing.*") || !strings.Contains(string(data), "io.microsoft.virtualmachine.*") {
				t.Fatal("lost required or existing pod annotations")
			}
			if config.GetPath([]string{"plugins", plugin, "containerd", "default_runtime_name"}) != "runhcs-sibling" ||
				config.GetPath([]string{"plugins", "io.containerd.cri.v1.images", "snapshotter"}) != "windows-lcow" ||
				config.GetPath([]string{"plugins", "io.containerd.cri.v1.images", "runtime_platforms", "runhcs-sibling", "platform"}) != "linux/amd64" ||
				config.GetPath([]string{"plugins", "io.containerd.cri.v1.images", "runtime_platforms", "runhcs-sibling", "snapshotter"}) != "windows-lcow" {
				t.Fatal("image pulls did not select the LCOW runtime and snapshotter")
			}
		})
	}
}

func TestIsolatedRuntimeRejectsMissingHandlerAndMalformedAnnotations(t *testing.T) {
	for _, input := range []string{
		"invalid = [",
		"version=3",
		`[plugins."io.containerd.cri.v1.runtime".containerd.runtimes.runhcs-lcow]
pod_annotations=[1]`,
		`[proxy_plugins.windows-lcow]
type='snapshot'
address='shared-snapshotter'
[plugins."io.containerd.cri.v1.runtime".containerd.runtimes.runhcs-lcow]
snapshotter='windows-lcow'`,
	} {
		if _, err := isolatedRuntimeConfig([]byte(input), `C:\owned`, `C:\runtime`, ""); err == nil {
			t.Fatalf("accepted invalid runtime configuration: %s", input)
		}
	}
}
