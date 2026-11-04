//go:build windows

package main

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"strings"
	"testing"

	"github.com/Microsoft/hcsshim/internal/cow"
	"github.com/Microsoft/hcsshim/internal/guest/prot"
	"github.com/opencontainers/runtime-spec/specs-go"
)

type helloTestProcess struct {
	cow.Process
	code int
}

func (p *helloTestProcess) Stdio() (io.Writer, io.Reader, io.Reader) {
	return nil, io.NopCloser(strings.NewReader("hello\n")), io.NopCloser(strings.NewReader(""))
}
func (p *helloTestProcess) Wait() error                       { return nil }
func (p *helloTestProcess) Pid() int                          { return 1 }
func (p *helloTestProcess) CloseStdout(context.Context) error { return nil }
func (p *helloTestProcess) CloseStderr(context.Context) error { return nil }
func (p *helloTestProcess) ExitCode() (int, error)            { return p.code, nil }
func (p *helloTestProcess) Close() error                      { return nil }

type helloTestContainer struct {
	cow.Container
	calls      *[]string
	done       chan struct{}
	startErr   error
	processErr error
	exitCode   int
}

func (c *helloTestContainer) IsOCI() bool { return true }
func (c *helloTestContainer) CreateProcess(_ context.Context, parameters interface{}) (cow.Process, error) {
	*c.calls = append(*c.calls, "init")
	data, _ := json.Marshal(parameters)
	var process map[string]interface{}
	if err := json.Unmarshal(data, &process); err != nil {
		return nil, err
	}
	if process["OciProcess"] != nil {
		return nil, errors.New("init was supplied an exec spec")
	}
	return &helloTestProcess{code: c.exitCode}, c.processErr
}
func (c *helloTestContainer) Start(context.Context) error {
	*c.calls = append(*c.calls, "start")
	return c.startErr
}
func (c *helloTestContainer) Terminate(context.Context) error {
	*c.calls = append(*c.calls, "terminate")
	close(c.done)
	return nil
}
func (c *helloTestContainer) WaitChannel() <-chan struct{} { return c.done }
func (c *helloTestContainer) WaitError() error             { return nil }
func (c *helloTestContainer) Close() error {
	*c.calls = append(*c.calls, "close")
	return nil
}

type helloTestHost struct {
	container *helloTestContainer
	deleteErr error
}

func (h helloTestHost) CreateContainer(context.Context, string, interface{}) (cow.Container, error) {
	*h.container.calls = append(*h.container.calls, "create")
	return h.container, nil
}
func (h helloTestHost) DeleteContainerState(context.Context, string) error {
	*h.container.calls = append(*h.container.calls, "delete")
	return h.deleteErr
}

func TestHelloContainerLifecycle(t *testing.T) {
	for _, scenario := range []struct {
		name                                        string
		startErr, processErr, unmountErr, deleteErr error
		code                                        int
		want                                        string
	}{
		{name: "success"},
		{name: "start failure", startErr: errors.New("start rejected"), want: "start rejected"},
		{name: "init failure", processErr: errors.New("init rejected"), want: "init rejected"},
		{name: "nonzero exit", code: 23, want: "exit code 23"},
		{name: "unmount failure", unmountErr: errors.New("still mounted"), want: "still mounted"},
		{name: "delete failure", deleteErr: errors.New("delete denied"), want: "delete denied"},
	} {
		t.Run(scenario.name, func(t *testing.T) {
			var calls []string
			container := &helloTestContainer{calls: &calls, done: make(chan struct{}),
				startErr: scenario.startErr, processErr: scenario.processErr, exitCode: scenario.code}
			result := &siblingHelloResult{ID: strings.Repeat("a", 64), ExitCode: -1}
			err := runHelloContainer(context.Background(), helloTestHost{container, scenario.deleteErr}, result, helloSettings(result.ID),
				func(context.Context) error { calls = append(calls, "unmount"); return scenario.unmountErr })
			if scenario.want == "" && err != nil || scenario.want != "" && (err == nil || !strings.Contains(err.Error(), scenario.want)) {
				t.Fatalf("error=%v, expected %q", err, scenario.want)
			}
			order := strings.Join(calls, ",")
			if !strings.HasSuffix(order, "terminate,unmount,delete,close") && scenario.unmountErr == nil {
				t.Fatalf("incorrect teardown order: %s", order)
			}
			if scenario.unmountErr != nil && strings.Contains(order, "delete") {
				t.Fatalf("deleted state while rootfs remained mounted: %s", order)
			}
			if scenario.startErr == nil && scenario.processErr == nil && (result.Stdout != "hello\n" || result.ExitCode != scenario.code) {
				t.Fatalf("output/exit status lost: %+v", result)
			}
		})
	}
}

func TestHelloSpecCreatesIsolatedInit(t *testing.T) {
	settings := helloSettings(strings.Repeat("b", 64))
	if settings.SchemaVersion.Cmp(prot.SchemaVersion{Major: 2, Minor: 1}) < 0 {
		t.Fatal("GCS requires a v2.1 hosted-container settings envelope")
	}
	spec := settings.OCISpecification
	if !spec.Root.Readonly || spec.Root.Path != settings.OCIBundlePath+"/rootfs" ||
		strings.Join(spec.Process.Args, " ") != "/hello" || spec.Process.Terminal || !spec.Process.NoNewPrivileges {
		t.Fatalf("unexpected hello spec: %+v", spec)
	}
	if spec.Windows == nil || spec.Windows.Network == nil ||
		spec.Windows.Network.NetworkNamespace != strings.Repeat("b", 64) {
		t.Fatal("GCS namespace bookkeeping ID must match the container cleanup ID")
	}
	namespaces := map[specs.LinuxNamespaceType]bool{}
	for _, namespace := range spec.Linux.Namespaces {
		if namespace.Path != "" {
			t.Fatal("hello joined a host namespace")
		}
		namespaces[namespace.Type] = true
	}
	if !namespaces[specs.PIDNamespace] || !namespaces[specs.MountNamespace] || namespaces[specs.NetworkNamespace] {
		t.Fatal("hello must isolate PID/mount while retaining existing workload networking")
	}
}

type helloNamespaceTestHost struct {
	helloTestHost
	assigned map[string]string
}

func (h *helloNamespaceTestHost) CreateContainer(ctx context.Context, id string, configuration interface{}) (cow.Container, error) {
	settings := configuration.(*prot.VMHostedContainerSettingsV2)
	namespaceID := ""
	if settings.OCISpecification.Windows != nil && settings.OCISpecification.Windows.Network != nil {
		namespaceID = settings.OCISpecification.Windows.Network.NetworkNamespace
	}
	if previous := h.assigned[namespaceID]; previous != "" {
		return nil, errors.New("previously assigned container pid to network namespace " + namespaceID)
	}
	h.assigned[namespaceID] = id
	return h.helloTestHost.CreateContainer(ctx, id, configuration)
}

func (h *helloNamespaceTestHost) DeleteContainerState(ctx context.Context, id string) error {
	if err := h.helloTestHost.DeleteContainerState(ctx, id); err != nil {
		return err
	}
	// GCS RemoveContainer removes namespace bookkeeping by container ID.
	delete(h.assigned, id)
	return nil
}

func TestHelloRepeatedContainerLifecycle(t *testing.T) {
	host := &helloNamespaceTestHost{assigned: map[string]string{}}
	var fixtures []*prot.VMHostedContainerSettingsV2
	for i := 0; i < 4; i++ {
		id := strings.Repeat(string(rune('a'+i)), 64)
		settings := helloSettings(id)
		if i%2 == 1 {
			image := &officialHelloImage{}
			image.config.Cmd = []string{"/hello"}
			image.config.Env = []string{"PATH=/usr/bin:/bin"}
			settings = image.settings(id)
		}
		fixtures = append(fixtures, settings)
		var calls []string
		host.container = &helloTestContainer{calls: &calls, done: make(chan struct{})}
		result := &siblingHelloResult{ID: id, ExitCode: -1}
		if err := runHelloContainer(context.Background(), host, result, settings,
			func(context.Context) error { return nil }); err != nil {
			t.Fatalf("run %d: %v", i+1, err)
		}
		if len(host.assigned) != 0 {
			t.Fatalf("run %d left namespace bookkeeping: %v", i+1, host.assigned)
		}
	}
	data, err := json.Marshal(fixtures)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("GCS_NETWORK_FIXTURES=%s", data)
}

func TestHelloRejectsWrongRoleAndMalformedRequest(t *testing.T) {
	for _, scenario := range []struct {
		role    string
		frame   byte
		payload []byte
	}{
		{"diode", frameHello, nil},
		{"diode", frameImageHello, nil},
		{"workload", frameHello, []byte("unexpected")},
		{"workload", frameImageHello, []byte("unexpected")},
	} {
		t.Run(scenario.role, func(t *testing.T) {
			server, client := net.Pipe()
			defer client.Close()
			done := make(chan struct{})
			go func() {
				defer close(done)
				defer server.Close()
				serveSiblingHello(context.Background(), nil, scenario.role, server, scenario.frame, scenario.payload)
			}()
			typ, data, err := readFrame(client)
			if err != nil || typ != scenario.frame {
				t.Fatalf("invalid result frame: %d %v", typ, err)
			}
			var result siblingHelloResult
			if err := json.Unmarshal(data, &result); err != nil {
				t.Fatal(err)
			}
			if result.Error == "" || result.ExitCode != -1 {
				t.Fatalf("false success: %+v", result)
			}
			<-done
		})
	}
}
