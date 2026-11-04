//go:build windows

package main

import (
	"reflect"
	"strings"
	"testing"

	"github.com/pelletier/go-toml"
)

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
`
			data, err := isolatedRuntimeConfig([]byte(input), `C:\owned`, `C:\runtime`)
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
			if !reflect.DeepEqual(config.GetPath(options).(*toml.Tree).ToMap(), original.GetPath(originalOptions).(*toml.Tree).ToMap()) {
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
		if _, err := isolatedRuntimeConfig([]byte(input), `C:\owned`, `C:\runtime`); err == nil {
			t.Fatalf("accepted invalid runtime configuration: %s", input)
		}
	}
}
