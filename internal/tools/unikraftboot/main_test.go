//go:build windows

package main

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const goodConsole = `hyperv: isolation type 2 (SNP), paravisor absent, shared GPA boundary 0x0
vmbus: version 5.3 accepted, 1 message(s), 1 synthetic interrupt(s)
vmbus: all offers delivered, 0 channel(s)
Hello world!
`

func TestSiblingProof(t *testing.T) {
	proof := goodConsole + `sibling: provider ready protocol=2
sibling: echo 16/16 replied; Linux peer must verify receipt
sibling: cleanup complete echo=16 doorbells=3 signals=5
`
	if err := requireSiblingMarkers([]byte(proof)); err != nil {
		t.Fatal(err)
	}
	for _, invalid := range []string{
		goodConsole,
		strings.ReplaceAll(proof, "echo 16/16", "echo 15/16"),
		strings.ReplaceAll(proof, "doorbells=3", "doorbells=0"),
		strings.ReplaceAll(proof, "cleanup complete", "cleanup failed"),
	} {
		if requireSiblingMarkers([]byte(invalid)) == nil {
			t.Fatal("accepted incomplete sibling proof")
		}
	}
}

func TestSiblingConfiguration(t *testing.T) {
	options := siblingOptions{
		Group:   "12345678-1234-1234-1234-123456789abc",
		Section: `\Sessions\1\BaseNamedObjects\owned-pair`, Length: 2 * 1024 * 1024,
	}
	if err := options.validate(); err != nil {
		t.Fatal(err)
	}
	config := snpConfiguration("owned", "state", "pipe")
	options.configure(config)
	data, err := json.Marshal(config)
	if err != nil {
		t.Fatal(err)
	}
	for _, expected := range []string{
		`"Role":"Backend"`, `"TargetSint":3`, `"EventFlagNumber":11`,
		`"SharedMemorySectionName"`, `"Length":2097152`, `"AllowGuestWrite":true`,
	} {
		if !strings.Contains(string(data), expected) {
			t.Fatalf("missing %s: %s", expected, data)
		}
	}
	for _, invalid := range []siblingOptions{
		{Group: options.Group}, {Section: options.Section},
		{Group: options.Group, Section: options.Section, Length: 1},
		{Group: options.Group, Section: options.Section, Length: 32 * 1024 * 1024},
	} {
		if invalid.validate() == nil {
			t.Fatal("accepted incomplete or unbounded sibling configuration")
		}
	}
}

func TestConfiguration(t *testing.T) {
	value := snpConfiguration("owned-id", `C:\test\guest.vmgs`, `\\.\pipe\unique`)
	encoded, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	text := string(encoded)
	for _, required := range []string{
		`"IsolationType":"SecureNestedPaging"`, `"HclEnabled":false`,
		`"ForceTransientState":true`, `"SizeInMB":34`, `"Count":1`,
		`"ShouldTerminateOnLastHandleClosed":true`, `"AllowOvercommit":false`,
	} {
		if !strings.Contains(text, required) {
			t.Errorf("missing %s: %s", required, text)
		}
	}
	for _, forbidden := range []string{"GuestConnection", "Plan9", "NetworkAdapters", "Scsi", "VirtualSmb"} {
		if strings.Contains(text, forbidden) {
			t.Errorf("unexpected Linux/EFI/device dependency: %s", forbidden)
		}
	}
	isolation := value["VirtualMachine"].(map[string]any)["SecuritySettings"].(map[string]any)["Isolation"].(map[string]any)
	launch, err := base64.StdEncoding.DecodeString(isolation["LaunchData"].(string))
	if err != nil || len(launch) != sha256.Size {
		t.Fatal("LaunchData must be a base64 SHA256, not an empty HCS field")
	}
}

type oneConnection struct{ net.Conn }

func (l *oneConnection) Accept() (net.Conn, error) { return l.Conn, nil }
func (l *oneConnection) Close() error              { return l.Conn.Close() }
func (l *oneConnection) Addr() net.Addr            { return l.Conn.LocalAddr() }

func TestConsoleCapture(t *testing.T) {
	for name, text := range map[string]string{
		"complete":   goodConsole,
		"incomplete": "Hello world!",
		"bounded":    strings.Repeat("x", consoleLimit+4096),
	} {
		t.Run(name, func(t *testing.T) {
			server, client := net.Pipe()
			defer server.Close()
			defer client.Close()
			producer := make(chan error, 1)
			go func() {
				_, err := io.WriteString(client, text)
				client.Close()
				producer <- err
			}()
			log, err := os.Create(filepath.Join(t.TempDir(), "console.log"))
			if err != nil {
				t.Fatal(err)
			}
			defer log.Close()
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			data, err := captureConsole(ctx, &oneConnection{server}, log)
			if (err == nil) != (name == "complete") || len(data) > consoleLimit {
				t.Fatalf("unexpected capture verdict/size: %v %d", err, len(data))
			}
			if name != "bounded" && string(data) != text {
				t.Fatal("console evidence was not preserved")
			}
			<-producer
		})
	}
}

func TestConsoleProof(t *testing.T) {
	if err := requireMarkers([]byte(goodConsole)); err != nil {
		t.Fatal(err)
	}
	for name, text := range map[string]string{
		"hello only":     "Hello world!",
		"no SNP":         strings.ReplaceAll(goodConsole, "isolation type 2 (SNP)", "isolation type 0"),
		"paravisor":      strings.ReplaceAll(goodConsole, "paravisor absent", "paravisor present"),
		"failed connect": strings.ReplaceAll(goodConsole, "version 5.3 accepted", "connect failed"),
		"failed offers":  strings.ReplaceAll(goodConsole, "all offers delivered, 0 channel(s)", "channel enumeration did not complete"),
		"no application": strings.ReplaceAll(goodConsole, "Hello world!", ""),
	} {
		t.Run(name, func(t *testing.T) {
			if requireMarkers([]byte(text)) == nil {
				t.Fatal("accepted incomplete boot evidence")
			}
		})
	}
}

func TestStateCopy(t *testing.T) {
	root := t.TempDir()
	source := filepath.Join(root, "source.vmgs")
	data := []byte("fresh template")
	if err := os.WriteFile(source, data, 0600); err != nil {
		t.Fatal(err)
	}
	hash := sha256.Sum256(data)
	expected := hex.EncodeToString(hash[:])
	for name, digest := range map[string]string{
		"correct":   expected,
		"incorrect": strings.Repeat("0", 64),
		"malformed": "x",
	} {
		t.Run(name, func(t *testing.T) {
			_, err := copyState(source, filepath.Join(root, name), digest)
			if (err == nil) != (name == "correct") {
				t.Fatalf("unexpected copy verdict: %v", err)
			}
		})
	}
	existing := filepath.Join(root, "existing.vmgs")
	if err := os.WriteFile(existing, []byte("owned elsewhere"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := copyState(source, existing, expected); err == nil {
		t.Fatal("replaced existing state")
	}
	got, err := os.ReadFile(existing)
	if err != nil || string(got) != "owned elsewhere" {
		t.Fatalf("existing state changed: %q %v", got, err)
	}
	got, err = os.ReadFile(source)
	if err != nil || string(got) != string(data) {
		t.Fatal("source template was modified")
	}
}

type fakeSystem struct {
	calls []string
	fail  string
}

func (s *fakeSystem) step(name string) error {
	s.calls = append(s.calls, name)
	if s.fail == name {
		return errors.New("injected " + name)
	}
	return nil
}
func (s *fakeSystem) Terminate(context.Context) error { return s.step("terminate") }
func (s *fakeSystem) WaitCtx(context.Context) error   { return s.step("wait") }
func (s *fakeSystem) Close() error                    { return s.step("close") }

func TestCleanup(t *testing.T) {
	for _, failure := range []string{"", "terminate", "wait", "close"} {
		t.Run(failure, func(t *testing.T) {
			system := &fakeSystem{fail: failure}
			checked := false
			err := cleanSystem(context.Background(), system, func(context.Context) (bool, error) {
				checked = true
				return true, nil
			})
			if (err != nil) != (failure != "") || !checked ||
				strings.Join(system.calls, ",") != "terminate,wait,close" {
				t.Fatalf("cleanup did not finish all operations: %v %v", err, system.calls)
			}
		})
	}
	t.Run("unknown presence", func(t *testing.T) {
		err := cleanSystem(context.Background(), nil, func(context.Context) (bool, error) {
			return false, errors.New("enumeration failed")
		})
		if err == nil {
			t.Fatal("unknown system presence was treated as absent")
		}
	})
	t.Run("still present", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), time.Millisecond)
		defer cancel()
		if err := cleanSystem(ctx, nil, func(context.Context) (bool, error) {
			return false, nil
		}); err == nil {
			t.Fatal("cleanup accepted a remaining HCS system")
		}
	})
}
