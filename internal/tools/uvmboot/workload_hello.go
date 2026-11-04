//go:build windows

package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"debug/elf"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/Microsoft/go-winio"
	"github.com/Microsoft/hcsshim/internal/cmd"
	"github.com/Microsoft/hcsshim/internal/cow"
	"github.com/Microsoft/hcsshim/internal/guest/prot"
	hcsschema "github.com/Microsoft/hcsshim/internal/hcs/schema2"
	"github.com/Microsoft/hcsshim/internal/uvm"
	"github.com/opencontainers/runtime-spec/specs-go"
	"github.com/urfave/cli"
)

const helloTimeout = 2 * time.Minute

type siblingHelloResult struct {
	ID       string `json:"id"`
	Stdout   string `json:"stdout"`
	Stderr   string `json:"stderr"`
	ExitCode int    `json:"exit_code"`
	Error    string `json:"error,omitempty"`
	Image    string `json:"image,omitempty"`
}

type helloOutput struct {
	mu     sync.Mutex
	buffer bytes.Buffer
}

func (b *helloOutput) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.buffer.Len()+len(p) > 8192 {
		return 0, errors.New("hello command output exceeds 8192 bytes")
	}
	return b.buffer.Write(p)
}

func (b *helloOutput) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buffer.String()
}

func helloSettings(id string) *prot.VMHostedContainerSettingsV2 {
	bundle := "/run/gcs/c/" + id
	return &prot.VMHostedContainerSettingsV2{
		SchemaVersion:  prot.SchemaVersion{Major: 2, Minor: 1},
		OCIBundlePath:  bundle,
		ScratchDirPath: bundle + "/scratch/" + id,
		OCISpecification: &specs.Spec{
			Version:  specs.Version,
			Hostname: "hello",
			Root:     &specs.Root{Path: bundle + "/rootfs", Readonly: true},
			// GCS uses this ID for bookkeeping and clears Windows before runc.
			Windows: &specs.Windows{Network: &specs.WindowsNetwork{NetworkNamespace: id}},
			Process: &specs.Process{
				Args:            []string{"/hello"},
				Cwd:             "/",
				Env:             []string{"PATH=/"},
				NoNewPrivileges: true,
				Capabilities:    &specs.LinuxCapabilities{},
			},
			Mounts: []specs.Mount{
				{Destination: "/proc", Type: "proc", Source: "proc", Options: []string{"nosuid", "noexec", "nodev"}},
				{Destination: "/dev", Type: "tmpfs", Source: "tmpfs", Options: []string{"nosuid", "strictatime", "mode=755", "size=1m"}},
			},
			Linux: &specs.Linux{
				CgroupsPath: "/workload-hello/" + id,
				Namespaces: []specs.LinuxNamespace{
					{Type: specs.PIDNamespace},
					{Type: specs.MountNamespace},
					{Type: specs.IPCNamespace},
					{Type: specs.UTSNamespace},
				},
			},
		},
	}
}

type helloContainerHost interface {
	CreateContainer(context.Context, string, interface{}) (cow.Container, error)
	DeleteContainerState(context.Context, string) error
}

func runHelloContainer(ctx context.Context, host helloContainerHost, result *siblingHelloResult, settings *prot.VMHostedContainerSettingsV2, unmount func(context.Context) error) (err error) {
	container, err := host.CreateContainer(ctx, result.ID, settings)
	if err != nil {
		return fmt.Errorf("create hello OCI container through GCS: %w", err)
	}
	defer func() {
		cleanup, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		select {
		case <-container.WaitChannel():
		default:
			if stopErr := container.Terminate(cleanup); stopErr != nil {
				err = errors.Join(err, fmt.Errorf("terminate hello container: %w", stopErr))
			}
		}
		select {
		case <-container.WaitChannel():
			if waitErr := container.WaitError(); waitErr != nil {
				err = errors.Join(err, fmt.Errorf("wait for hello container: %w", waitErr))
			} else if unmountErr := unmount(cleanup); unmountErr != nil {
				err = errors.Join(err, fmt.Errorf("unmount hello rootfs: %w", unmountErr))
			} else if deleteErr := host.DeleteContainerState(cleanup, result.ID); deleteErr != nil {
				err = errors.Join(err, fmt.Errorf("delete hello container state: %w", deleteErr))
			}
		case <-cleanup.Done():
			err = errors.Join(err, fmt.Errorf("hello container teardown: %w", cleanup.Err()))
		}
		err = errors.Join(err, container.Close())
	}()
	if err := container.Start(ctx); err != nil {
		return fmt.Errorf("start hello container: %w", err)
	}
	var stdout, stderr helloOutput
	// Omitting an OCI process spec starts the existing init, rather than exec.
	result.ExitCode, err = runHelloProcess(ctx, container, &hcsschema.ProcessParameters{
		CreateStdOutPipe: true, CreateStdErrPipe: true,
	}, &stdout, &stderr)
	result.Stdout, result.Stderr = stdout.String(), stderr.String()
	if err != nil {
		return fmt.Errorf("run hello container init: %w", err)
	}
	return nil
}

func helloGuestCommand(ctx context.Context, vm cow.ProcessHost, script string) (string, error) {
	var output helloOutput
	_, err := runHelloProcess(ctx, vm, &hcsschema.ProcessParameters{
		CommandArgs: []string{"sh", "-c", script}, WorkingDirectory: "/",
		Environment:      map[string]string{"PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"},
		CreateStdOutPipe: true, CreateStdErrPipe: true,
	}, &output, &output)
	if err != nil {
		return output.String(), fmt.Errorf("hello guest command: %w: %s", err, output.String())
	}
	return output.String(), nil
}

func runHelloProcess(ctx context.Context, host cow.ProcessHost, parameters interface{}, stdout, stderr io.Writer) (int, error) {
	process, err := host.CreateProcess(ctx, parameters)
	if err != nil {
		return -1, err
	}
	command, err := cmd.Attach(ctx, process, nil, stdout, stderr)
	if err != nil {
		return -1, errors.Join(err, process.Close())
	}
	command.CopyAfterExitTimeout = 5 * time.Second
	err = command.Wait()
	return command.ExitState.ExitCode(), err
}

func runSiblingHello(ctx context.Context, vm *uvm.UtilityVM, result *siblingHelloResult, image *officialHelloImage) (err error) {
	if !vm.DeleteContainerStateSupported() {
		return errors.New("workload GCS does not support container-state deletion; cannot run hello with reliable cleanup")
	}
	executable, err := os.Executable()
	if err != nil {
		return err
	}
	payload := filepath.Join(filepath.Dir(executable), "workload-hello")
	if image != nil {
		file, createErr := os.CreateTemp("", "workload-image-hello-*")
		if createErr != nil {
			return createErr
		}
		payload = file.Name()
		defer func() { err = errors.Join(err, os.Remove(payload)) }()
		_, writeErr := file.Write(image.payload)
		if err := errors.Join(writeErr, file.Close()); err != nil {
			return fmt.Errorf("stage downloaded /hello: %w", err)
		}
	}
	binary, err := elf.Open(payload)
	if err != nil {
		return fmt.Errorf("open bundled Linux hello payload: %w", err)
	}
	valid := binary.Machine == elf.EM_X86_64 && binary.Class == elf.ELFCLASS64
	for _, program := range binary.Progs {
		if program.Type == elf.PT_INTERP {
			valid = false
		}
	}
	if err := binary.Close(); err != nil {
		return err
	}
	if !valid {
		return errors.New("workload-hello must be a static Linux amd64 executable")
	}
	var random [32]byte
	if _, err := rand.Read(random[:]); err != nil {
		return err
	}
	result.ID = hex.EncodeToString(random[:])
	settings := helloSettings(result.ID)
	mode := os.FileMode(0555)
	if image != nil {
		settings = image.settings(result.ID)
		mode = image.mode
	}
	bundle := settings.OCIBundlePath
	rootfs := settings.OCISpecification.Root.Path
	sharePath := "/run/workload-hello-share-" + result.ID
	share, err := vm.AddPlan9(ctx, filepath.Dir(payload), sharePath, true, true, []string{filepath.Base(payload)})
	if err != nil {
		return fmt.Errorf("stage hello payload in workload: %w", err)
	}
	defer func() {
		cleanup, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		if releaseErr := share.Release(cleanup); releaseErr != nil {
			err = errors.Join(err, fmt.Errorf("release hello payload share: %w", releaseErr))
		}
	}()
	if _, err := helloGuestCommand(ctx, vm,
		"set -eu; command -v runc >/dev/null; command -v mountpoint >/dev/null; test -d /sys/fs/cgroup; "+
			"mkdir -p /run/gcs/c; mkdir "+shellSingleQuote(bundle)); err != nil {
		return err
	}
	unmount := func(cleanup context.Context) error {
		_, err := helloGuestCommand(cleanup, vm, "set -eu; if mountpoint -q "+
			shellSingleQuote(rootfs)+"; then umount "+shellSingleQuote(rootfs)+"; fi")
		return err
	}
	mayHaveContainer := false
	defer func() {
		if mayHaveContainer {
			err = fmt.Errorf("%w (inspect container %s and bundle %s)", err, result.ID, bundle)
			return
		}
		cleanup, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		if unmountErr := unmount(cleanup); unmountErr != nil {
			err = errors.Join(err, unmountErr)
			return
		}
		_, removeErr := helloGuestCommand(cleanup, vm, "set -eu; rm -rf -- "+shellSingleQuote(bundle))
		err = errors.Join(err, removeErr)
	}()
	stage := "set -eu; mkdir -p " + shellSingleQuote(rootfs) + " " + shellSingleQuote(settings.ScratchDirPath) + "; " +
		"mount -t tmpfs -o exec,nosuid,nodev,size=32m,mode=0755 tmpfs " + shellSingleQuote(rootfs) + "; " +
		"mkdir -p " + shellSingleQuote(rootfs+"/proc") + " " + shellSingleQuote(rootfs+"/dev") + " " +
		shellSingleQuote(rootfs+"/etc") + "; " +
		"cp " + shellSingleQuote(sharePath+"/"+filepath.Base(payload)) + " " + shellSingleQuote(rootfs+"/hello") + "; " +
		fmt.Sprintf("chmod %04o ", mode) + shellSingleQuote(rootfs+"/hello") + "; " +
		"readlink /proc/self/ns/pid; readlink /proc/self/ns/mnt"
	namespaces, err := helloGuestCommand(ctx, vm, stage)
	if err != nil {
		return err
	}
	mayHaveContainer = true
	host := &helloTrackedHost{helloContainerHost: vm}
	if err := runHelloContainer(ctx, host, result, settings, unmount); err != nil {
		mayHaveContainer = !host.deleted
		return err
	}
	mayHaveContainer = false
	if image != nil {
		if result.ExitCode != 0 || !strings.Contains(result.Stdout, "Hello from Docker!") {
			return errors.New("official hello-world did not exit successfully with its expected greeting")
		}
		return nil
	}
	var proof struct {
		Message        string `json:"message"`
		PID            int    `json:"pid"`
		PIDNamespace   string `json:"pid_namespace"`
		MountNamespace string `json:"mount_namespace"`
	}
	if err := json.Unmarshal([]byte(result.Stdout), &proof); err != nil {
		return fmt.Errorf("decode hello namespace proof: %w", err)
	}
	hostNamespaces := strings.Fields(namespaces)
	if len(hostNamespaces) != 2 || proof.PID != 1 || proof.PIDNamespace == "" ||
		proof.MountNamespace == "" || proof.PIDNamespace == hostNamespaces[0] ||
		proof.MountNamespace == hostNamespaces[1] {
		return errors.New("hello did not establish separate container PID/mount namespaces")
	}
	return nil
}

type helloTrackedHost struct {
	helloContainerHost
	deleted bool
}

func (h *helloTrackedHost) DeleteContainerState(ctx context.Context, id string) error {
	err := h.helloContainerHost.DeleteContainerState(ctx, id)
	h.deleted = err == nil
	return err
}

func serveSiblingHello(parent context.Context, vm *uvm.UtilityVM, name string, conn net.Conn, frame byte, payload []byte) {
	ctx, cancel := context.WithTimeout(parent, helloTimeout)
	defer cancel()
	if err := conn.SetDeadline(time.Now().Add(helloTimeout + 2*time.Minute)); err != nil {
		fmt.Fprintf(os.Stderr, "hello connection deadline: %v\n", err)
		return
	}
	go func() {
		var extra [1]byte
		_, _ = conn.Read(extra[:])
		cancel()
	}()
	result := siblingHelloResult{ExitCode: -1}
	var err error
	if name != "workload" || len(payload) != 0 || (frame != frameHello && frame != frameImageHello) {
		err = errors.New("hello requires the workload endpoint and an empty request")
	} else {
		var image *officialHelloImage
		if frame == frameImageHello {
			result.Image = officialHelloReference
			image, err = pullOfficialHello(ctx)
		}
		if err == nil {
			err = runSiblingHello(ctx, vm, &result, image)
		}
	}
	if err != nil {
		result.Error = err.Error()
	}
	response, marshalErr := json.Marshal(result)
	if marshalErr != nil {
		fmt.Fprintf(os.Stderr, "hello response: %v\n", marshalErr)
		return
	}
	if len(response) > 65535 {
		response, _ = json.Marshal(siblingHelloResult{ID: result.ID, ExitCode: -1,
			Error: "hello result exceeded the control frame limit; output omitted"})
	}
	if err := writeFrame(conn, frame, response); err != nil {
		fmt.Fprintf(os.Stderr, "hello response delivery: %v\n", err)
	}
}

var siblingContainerCommand = cli.Command{
	Name:      "container",
	Usage:     "Run bundled hello or downloaded official hello-world in the running workload UVM",
	ArgsUsage: "hello|hello-world",
	Action: func(c *cli.Context) error {
		if c.NArg() != 1 || (c.Args().First() != "hello" && c.Args().First() != "hello-world") {
			return errors.New("usage: container hello|hello-world")
		}
		frame := byte(frameHello)
		if c.Args().First() == "hello-world" {
			frame = frameImageHello
		}
		timeout := 5 * time.Second
		conn, err := winio.DialPipe(siblingPipePrefix+"workload", &timeout)
		if err != nil {
			return fmt.Errorf("connect to workload (start the pair with run.ps1 diode start first): %w", err)
		}
		defer conn.Close()
		if err := conn.SetDeadline(time.Now().Add(helloTimeout + 2*time.Minute)); err != nil {
			return err
		}
		if frame == frameImageHello {
			fmt.Printf("Pulling official Linux/amd64 image: %s\n", officialHelloReference)
		}
		if err := writeFrame(conn, frame, nil); err != nil {
			return err
		}
		typ, payload, err := readFrame(conn)
		if err != nil {
			return fmt.Errorf("read hello result (restart the pair if its launcher predates container support): %w", err)
		}
		if typ != frame {
			return fmt.Errorf("unexpected hello response type %d", typ)
		}
		var result siblingHelloResult
		if err := json.Unmarshal(payload, &result); err != nil {
			return fmt.Errorf("decode hello result: %w", err)
		}
		if _, err := io.WriteString(os.Stdout, result.Stdout); err != nil {
			return err
		}
		if _, err := io.WriteString(os.Stderr, result.Stderr); err != nil {
			return err
		}
		if result.Error != "" {
			if result.ExitCode > 0 {
				return cli.NewExitError(result.Error, result.ExitCode)
			}
			return errors.New(result.Error)
		}
		if result.ExitCode != 0 {
			return cli.NewExitError("hello container failed", result.ExitCode)
		}
		if frame == frameImageHello {
			if result.Image != officialHelloReference {
				return errors.New("official hello-world response image does not match the requested digest")
			}
			fmt.Printf("PASS: official hello-world container %s exited 0; cleanup verified\n", result.ID)
		} else {
			fmt.Printf("PASS: workload OCI hello container %s exited 0; PID/mount isolation and cleanup verified\n", result.ID)
		}
		return nil
	},
}
