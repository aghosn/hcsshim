//go:build windows

package main

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/Microsoft/go-winio"
	"github.com/Microsoft/go-winio/pkg/guid"
	"github.com/Microsoft/hcsshim/internal/hcs"
	"github.com/Microsoft/hcsshim/internal/hcs/schema1"
	hcsschema "github.com/Microsoft/hcsshim/internal/hcs/schema2"
	"github.com/Microsoft/hcsshim/internal/security"
	"github.com/Microsoft/hcsshim/internal/winapi"
	"golang.org/x/sys/windows"
)

const consoleLimit = 4 * 1024 * 1024

var bootMarkers = []*regexp.Regexp{
	regexp.MustCompile(`hyperv: isolation type 2 \(SNP\), paravisor absent`),
	regexp.MustCompile(`vmbus: version [0-9]+\.[0-9]+ accepted`),
	regexp.MustCompile(`vmbus: all offers delivered, [0-9]+ channel\(s\)`),
	regexp.MustCompile(`Hello world!`),
}

var siblingMarkers = []*regexp.Regexp{
	regexp.MustCompile(`sibling: provider ready protocol=2`),
	regexp.MustCompile(`sibling: echo 16/16 replied`),
	regexp.MustCompile(`sibling: cleanup complete echo=16 doorbells=[1-9][0-9]* signals=[1-9][0-9]*`),
}

type siblingOptions struct {
	Group   string
	Section string
	Length  int
}

func (s siblingOptions) validate() error {
	if s.Group == "" && s.Section == "" && s.Length == 0 {
		return nil
	}
	if _, err := guid.FromString(s.Group); err != nil {
		return fmt.Errorf("invalid sibling group: %w", err)
	}
	if !strings.HasPrefix(s.Section, `\Sessions\`) ||
		!strings.Contains(s.Section, `\BaseNamedObjects\`) ||
		s.Length < 0x20000 || s.Length > 16*1024*1024 || s.Length%4096 != 0 {
		return errors.New("sibling mode requires a named HCS section and a page-aligned length from 128 KiB to 16 MiB")
	}
	return nil
}

func (s siblingOptions) configure(configuration map[string]any) {
	if s.Group == "" {
		return
	}
	devices := configuration["VirtualMachine"].(map[string]any)["Devices"].(map[string]any)
	devices["SharedMemory"] = hcsschema.SharedMemoryConfiguration{
		Regions: []hcsschema.SharedMemoryRegion{{
			SectionName: s.Section, Length: int32(s.Length), AllowGuestWrite: true,
		}},
	}
	devices["SiblingCommunicationEndpoints"] = []hcsschema.SiblingCommunicationEndpoint{{
		GroupID: s.Group, Role: hcsschema.SiblingCommunicationEndpointRoleBackend,
		TargetSINT: 3, EventFlagNumber: 11, SharedMemorySectionName: s.Section,
	}}
}

func requireSiblingMarkers(data []byte) error {
	if err := requireMarkers(data); err != nil {
		return err
	}
	for _, marker := range siblingMarkers {
		if !marker.Match(data) {
			return fmt.Errorf("missing sibling marker: %s", marker)
		}
	}
	return nil
}

type bootReport struct {
	Result            string   `json:"result"`
	Scope             string   `json:"scope"`
	SystemID          string   `json:"system_id"`
	SourceSHA256      string   `json:"source_sha256"`
	Console           string   `json:"console_log"`
	Configuration     string   `json:"hcs_config"`
	MarkersSeen       []bool   `json:"markers_seen"`
	Cleanup           bool     `json:"cleanup_complete"`
	Error             string   `json:"error,omitempty"`
	CleanupErrors     []string `json:"cleanup_errors,omitempty"`
	SiblingLinkTested bool     `json:"sibling_link_tested"`
	AttestationTested bool     `json:"attestation_tested"`
}

func snpConfiguration(id, state, pipe string) map[string]any {
	launchData := sha256.Sum256([]byte("unikraft-discovery-" + id))
	return map[string]any{
		"SchemaVersion":                     map[string]int{"Major": 2, "Minor": 5},
		"Owner":                             "unikraft-discovery-" + id,
		"ShouldTerminateOnLastHandleClosed": true,
		"VirtualMachine": map[string]any{
			"StopOnReset": true,
			"Chipset": map[string]any{"Uefi": map[string]any{
				"ApplySecureBootTemplate": "Apply",
				"SecureBootTemplateId":    "1734c6e8-3154-4dda-ba5f-a874cc483422",
			}},
			"ComputeTopology": map[string]any{
				"Memory":    map[string]any{"SizeInMB": 34, "AllowOvercommit": false},
				"Processor": map[string]int{"Count": 1},
			},
			"GuestState": map[string]any{
				"GuestStateFilePath":  state,
				"GuestStateFileType":  "FileMode",
				"ForceTransientState": true,
			},
			"SecuritySettings": map[string]any{
				"EnableTpm": false,
				"Isolation": map[string]any{
					"IsolationType": "SecureNestedPaging",
					"LaunchData":    base64.StdEncoding.EncodeToString(launchData[:]),
					"HclEnabled":    false,
				},
			},
			"Devices": map[string]any{
				"ComPorts": map[string]any{"0": map[string]string{"NamedPipe": pipe}},
			},
		},
	}
}

func markersSeen(data []byte) []bool {
	seen := make([]bool, len(bootMarkers))
	for i, marker := range bootMarkers {
		seen[i] = marker.Match(data)
	}
	return seen
}

func requireMarkers(data []byte) error {
	for _, marker := range bootMarkers {
		if !marker.Match(data) {
			return fmt.Errorf("missing guest marker: %s", marker)
		}
	}
	return nil
}

func copyState(source, destination, expected string) (digest string, err error) {
	if raw, e := hex.DecodeString(expected); e != nil || len(raw) != sha256.Size {
		return "", errors.New("expected VMGS SHA256 must contain 64 hex digits")
	}
	input, err := os.Open(source)
	if err != nil {
		return "", err
	}
	defer input.Close()
	output, err := os.OpenFile(destination, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return "", err
	}
	hash := sha256.New()
	count, copyErr := io.Copy(io.MultiWriter(output, hash), input)
	err = errors.Join(copyErr, output.Sync(), output.Close())
	if err != nil {
		return "", err
	}
	digest = hex.EncodeToString(hash.Sum(nil))
	if count == 0 || !strings.EqualFold(digest, expected) {
		return digest, errors.New("staged VMGS does not match the package SHA256")
	}
	return digest, nil
}

func captureConsole(ctx context.Context, listener net.Listener, log *os.File) ([]byte, error) {
	return captureConsoleUntil(ctx, listener, log, requireMarkers)
}

func captureConsoleUntil(ctx context.Context, listener net.Listener, log *os.File, proof func([]byte) error) ([]byte, error) {
	connection, err := listener.Accept()
	if err != nil {
		return nil, err
	}
	defer connection.Close()
	var data []byte
	buffer := make([]byte, 4096)
	for {
		if err := connection.SetReadDeadline(time.Now().Add(250 * time.Millisecond)); err != nil {
			return data, err
		}
		count, readErr := connection.Read(buffer)
		if count > 0 {
			if len(data)+count > consoleLimit {
				return data, errors.New("guest console exceeded 4 MiB")
			}
			if _, err := log.Write(buffer[:count]); err != nil {
				return data, err
			}
			data = append(data, buffer[:count]...)
			if proof(data) == nil {
				return data, nil
			}
		}
		if ctx.Err() != nil {
			return data, ctx.Err()
		}
		if readErr != nil {
			var timeout net.Error
			if errors.As(readErr, &timeout) && timeout.Timeout() {
				continue
			}
			return data, errors.Join(readErr, proof(data))
		}
	}
}

type bootSystem interface {
	Terminate(context.Context) error
	WaitCtx(context.Context) error
	Close() error
}

func cleanSystem(ctx context.Context, system bootSystem, absent func(context.Context) (bool, error)) error {
	var cleanupErr error
	if system != nil {
		cleanupErr = errors.Join(system.Terminate(ctx), system.WaitCtx(ctx), system.Close())
	}
	for {
		gone, err := absent(ctx)
		if err != nil {
			return errors.Join(cleanupErr, err)
		}
		if gone {
			return cleanupErr
		}
		select {
		case <-ctx.Done():
			return errors.Join(cleanupErr, ctx.Err())
		case <-time.After(100 * time.Millisecond):
		}
	}
}

func localOutput(path string) (string, error) {
	absolute, err := filepath.Abs(path)
	if err != nil {
		return "", err
	}
	volume := filepath.VolumeName(absolute)
	if len(volume) != 2 || volume[1] != ':' {
		return "", errors.New("output must be on a local Windows drive")
	}
	root, err := windows.UTF16PtrFromString(volume + `\`)
	if err != nil {
		return "", err
	}
	drive := windows.GetDriveType(root)
	if drive != windows.DRIVE_FIXED && drive != windows.DRIVE_REMOVABLE {
		return "", errors.New("output must not be a mapped network drive")
	}
	for parent := absolute; ; parent = filepath.Dir(parent) {
		info, err := os.Lstat(parent)
		if err == nil {
			if !info.IsDir() || info.Mode()&(os.ModeSymlink|os.ModeIrregular) != 0 {
				return "", fmt.Errorf("output ancestor is not a real directory: %s", parent)
			}
		} else if !os.IsNotExist(err) {
			return "", err
		}
		if filepath.Dir(parent) == parent {
			break
		}
	}
	return absolute, nil
}

func boot(source, expected, output string, timeout time.Duration, sibling siblingOptions) (run string, err error) {
	if err := sibling.validate(); err != nil {
		return "", err
	}
	if !winapi.IsElevated() {
		return "", errors.New("run from elevated PowerShell")
	}
	root, err := localOutput(output)
	if err != nil {
		return "", err
	}
	id, err := guid.NewV4()
	if err != nil {
		return "", err
	}
	systemID := id.String()
	run = filepath.Join(root, "unikraft-"+systemID)
	if err = os.MkdirAll(root, 0700); err != nil {
		return "", err
	}
	if err = os.Mkdir(run, 0700); err != nil {
		return "", err
	}
	state := filepath.Join(run, "guest.vmgs")
	report := bootReport{
		Result: "FAIL", SystemID: systemID,
		Scope:         "Direct SNP boot and root VMBus discovery; not sibling interoperability or attestation",
		Console:       filepath.Join(run, "console.log"),
		Configuration: filepath.Join(run, "hcs-config.json"),
	}
	proof := requireMarkers
	if sibling.Group != "" {
		report.Scope = "Direct SNP provider: sibling control, 16 echo replies, inbound doorbells and guest teardown; Linux receipt checked by pair launcher"
		proof = requireSiblingMarkers
	}
	var system *hcs.System
	creationAttempted := false
	defer func() {
		cleanupCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		var cleanupErr error
		if creationAttempted {
			var owned bootSystem
			if system != nil {
				owned = system
			}
			cleanupErr = cleanSystem(cleanupCtx, owned, func(ctx context.Context) (bool, error) {
				systems, e := hcs.GetComputeSystems(ctx, schema1.ComputeSystemQuery{IDs: []string{systemID}})
				return len(systems) == 0, e
			})
		}
		if cleanupErr == nil {
			if e := os.Remove(state); e != nil && !os.IsNotExist(e) {
				cleanupErr = e
			}
		}
		report.Cleanup = cleanupErr == nil
		if cleanupErr != nil {
			report.CleanupErrors = []string{cleanupErr.Error()}
		}
		err = errors.Join(err, cleanupErr)
		if err == nil {
			report.Result = "PASS"
		} else {
			report.Error = err.Error()
		}
		data, e := json.MarshalIndent(report, "", "  ")
		if e == nil {
			e = os.WriteFile(filepath.Join(run, "result.json"), data, 0600)
		}
		err = errors.Join(err, e)
	}()
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	existing, err := hcs.GetComputeSystems(ctx, schema1.ComputeSystemQuery{IDs: []string{systemID}})
	if err != nil {
		return run, err
	}
	if len(existing) != 0 {
		return run, errors.New("generated HCS ID already exists; nothing was modified")
	}
	report.SourceSHA256, err = copyState(source, state, expected)
	if err != nil {
		return run, err
	}
	if err = security.GrantVmGroupAccessWithMask(state, security.AccessMaskAll); err != nil {
		return run, err
	}
	pipe := `\\.\pipe\unikraft-` + systemID
	listener, err := winio.ListenPipe(pipe, &winio.PipeConfig{
		SecurityDescriptor: "D:P(A;;GA;;;SY)(A;;GA;;;BA)",
	})
	if err != nil {
		return run, err
	}
	defer listener.Close()
	log, err := os.OpenFile(report.Console, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return run, err
	}
	type capture struct {
		data []byte
		err  error
	}
	done := make(chan capture, 1)
	go func() {
		data, e := captureConsoleUntil(ctx, listener, log, proof)
		done <- capture{data, errors.Join(e, log.Close())}
	}()
	// Closing the listener unblocks Accept; read deadlines bound an active read.
	defer func() {
		cancel()
		listener.Close()
		result := <-done
		report.MarkersSeen = markersSeen(result.data)
		if sibling.Group != "" {
			report.SiblingLinkTested = requireSiblingMarkers(result.data) == nil
		}
		err = errors.Join(err, result.err)
	}()
	configuration := snpConfiguration(systemID, state, pipe)
	sibling.configure(configuration)
	config, err := json.MarshalIndent(configuration, "", "  ")
	if err != nil {
		return run, err
	}
	if err = os.WriteFile(report.Configuration, config, 0600); err != nil {
		return run, err
	}
	creationAttempted = true
	system, err = hcs.CreateComputeSystem(ctx, systemID, configuration)
	if err != nil {
		return run, err
	}
	if err = system.Start(ctx); err != nil {
		return run, err
	}
	select {
	case result := <-done:
		// Leave the completed capture for the deferred report/close path.
		done <- result
		err = result.err
	case <-ctx.Done():
		err = ctx.Err()
	}
	return run, err
}

func main() {
	source := flag.String("vmgs", "", "Packaged direct-SNP VMGS template")
	expected := flag.String("sha256", "", "Expected template SHA256")
	output := flag.String("output", "results", "Local Windows results directory")
	timeout := flag.Duration("timeout", 90*time.Second, "Boot and console timeout")
	group := flag.String("sibling-group", "", "Existing mixed-pair sibling group GUID")
	section := flag.String("sibling-section", "", "Existing shared section HCS object name")
	length := flag.Int("sibling-length", 0, "Existing shared section length in bytes")
	flag.Parse()
	if flag.NArg() != 0 || *source == "" || *expected == "" || *timeout < 15*time.Second || *timeout > 180*time.Second {
		fmt.Fprintln(os.Stderr, "usage: unikraftboot -vmgs FILE -sha256 HASH [-output DIRECTORY] [-timeout 90s]")
		os.Exit(2)
	}
	run, err := boot(*source, *expected, *output, *timeout,
		siblingOptions{Group: *group, Section: *section, Length: *length})
	fmt.Println("Results:", run)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	if *group != "" {
		fmt.Println("PASS: direct SNP sibling provider echoed 16 packets, received doorbells and cleaned up")
	} else {
		fmt.Println("PASS: direct SNP boot and root VMBus discovery (sibling link not tested)")
	}
}
