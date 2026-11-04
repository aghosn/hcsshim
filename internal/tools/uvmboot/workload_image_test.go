//go:build windows

package main

import (
	"archive/tar"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"io"
	"os"
	"strings"
	"testing"
	"time"

	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/opencontainers/runtime-spec/specs-go"
)

func helloTestELF() []byte {
	data := make([]byte, 64)
	copy(data, []byte{0x7f, 'E', 'L', 'F', 2, 1, 1})
	binary.LittleEndian.PutUint16(data[16:], 2)
	binary.LittleEndian.PutUint16(data[18:], 62)
	binary.LittleEndian.PutUint32(data[20:], 1)
	binary.LittleEndian.PutUint16(data[52:], 64)
	binary.LittleEndian.PutUint16(data[54:], 56)
	binary.LittleEndian.PutUint16(data[58:], 64)
	return data
}

func helloTestTar(t *testing.T, headers ...tar.Header) []byte {
	t.Helper()
	var buffer bytes.Buffer
	writer := tar.NewWriter(&buffer)
	for _, header := range headers {
		if err := writer.WriteHeader(&header); err != nil {
			t.Fatal(err)
		}
		if header.Typeflag == tar.TypeReg {
			if _, err := writer.Write(helloTestELF()[:header.Size]); err != nil {
				t.Fatal(err)
			}
		}
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	return buffer.Bytes()
}

func TestOfficialHelloRootfs(t *testing.T) {
	header := tar.Header{Name: "hello", Typeflag: tar.TypeReg, Mode: 0755, Size: 64}
	for _, scenario := range []struct {
		name   string
		change func(*tar.Header)
		extra  bool
		valid  bool
	}{
		{name: "official scratch executable", valid: true},
		{name: "dot prefix", change: func(h *tar.Header) { h.Name = "./hello" }, valid: true},
		{name: "traversal", change: func(h *tar.Header) { h.Name = "../hello" }},
		{name: "absolute path", change: func(h *tar.Header) { h.Name = "/hello" }},
		{name: "windows path", change: func(h *tar.Header) { h.Name = `C:\hello` }},
		{name: "whiteout", change: func(h *tar.Header) { h.Name = ".wh.hello" }},
		{name: "symlink", change: func(h *tar.Header) { h.Typeflag = tar.TypeSymlink; h.Size = 0; h.Linkname = "/bin/sh" }},
		{name: "hardlink", change: func(h *tar.Header) { h.Typeflag = tar.TypeLink; h.Size = 0; h.Linkname = "/etc/passwd" }},
		{name: "setuid", change: func(h *tar.Header) { h.Mode = 04755 }},
		{name: "not executable", change: func(h *tar.Header) { h.Mode = 0644 }},
		{name: "nonroot owner", change: func(h *tar.Header) { h.Uid = 1000 }},
		{name: "duplicate executable", extra: true},
	} {
		t.Run(scenario.name, func(t *testing.T) {
			current := header
			if scenario.change != nil {
				scenario.change(&current)
			}
			headers := []tar.Header{current}
			if scenario.extra {
				headers = append(headers, header)
			}
			payload, mode, err := unpackOfficialHello(helloTestTar(t, headers...))
			if scenario.valid {
				if err != nil || mode != 0755 || !bytes.Equal(payload, helloTestELF()) {
					t.Fatalf("payload=%x mode=%o error=%v", payload, mode, err)
				}
			} else if err == nil {
				t.Fatal("unsupported archive accepted")
			}
		})
	}
	for _, data := range [][]byte{nil, []byte("not a tar"), helloTestTar(t)} {
		if _, _, err := unpackOfficialHello(data); err == nil {
			t.Fatal("missing or malformed rootfs accepted")
		}
	}
}

type helloConfigImage struct {
	v1.Image
	config *v1.ConfigFile
	layers []v1.Layer
}

func (i helloConfigImage) ConfigFile() (*v1.ConfigFile, error) { return i.config, nil }
func (i helloConfigImage) Layers() ([]v1.Layer, error)         { return i.layers, nil }

type helloTestLayer struct {
	v1.Layer
	data []byte
}

func (l helloTestLayer) Uncompressed() (io.ReadCloser, error) {
	return io.NopCloser(bytes.NewReader(l.data)), nil
}

func TestOfficialHelloImageConfigurationAndIntegrity(t *testing.T) {
	data := helloTestTar(t, tar.Header{
		Name: "hello", Typeflag: tar.TypeReg, Mode: 0755, Size: 64,
	})
	diffID, _, err := v1.SHA256(bytes.NewReader(data))
	if err != nil {
		t.Fatal(err)
	}
	for _, scenario := range []string{"valid", "wrong platform", "wrong command", "nonroot user", "volume", "wrong diffID", "missing diffID", "missing layer", "multiple layers", "oversized layer"} {
		t.Run(scenario, func(t *testing.T) {
			config := &v1.ConfigFile{
				OS: "linux", Architecture: "amd64",
				RootFS: v1.RootFS{Type: "layers", DiffIDs: []v1.Hash{diffID}},
				Config: v1.Config{Cmd: []string{"/hello"}, Env: []string{"PATH=/from-image"}},
			}
			image := helloConfigImage{config: config, layers: []v1.Layer{helloTestLayer{data: data}}}
			switch scenario {
			case "wrong platform":
				config.Architecture = "arm64"
			case "wrong command":
				config.Config.Cmd = []string{"/bin/sh"}
			case "nonroot user":
				config.Config.User = "1000"
			case "volume":
				config.Config.Volumes = map[string]struct{}{"/data": {}}
			case "wrong diffID":
				config.RootFS.DiffIDs[0] = v1.Hash{Algorithm: "sha256", Hex: strings.Repeat("0", 64)}
			case "missing diffID":
				config.RootFS.DiffIDs = nil
			case "missing layer":
				image.layers = nil
			case "multiple layers":
				image.layers = append(image.layers, image.layers[0])
			case "oversized layer":
				image.layers = []v1.Layer{helloTestLayer{data: make([]byte, helloLayerLimit+1)}}
			}
			result, err := readOfficialHello(image)
			if scenario == "valid" {
				if err != nil || !bytes.Equal(result.payload, helloTestELF()) ||
					result.config.Env[0] != "PATH=/from-image" || result.config.Cmd[0] != "/hello" {
					t.Fatalf("image not preserved: %+v error=%v", result, err)
				}
			} else if err == nil {
				t.Fatal("invalid configuration/integrity accepted")
			}
		})
	}
}

func TestOfficialHelloSettingsPreserveImageAndIsolation(t *testing.T) {
	image := &officialHelloImage{config: v1.Config{
		Entrypoint: []string{"/hello"}, Env: []string{"PATH=/from-image"},
	}}
	settings := image.settings(strings.Repeat("c", 64))
	spec := settings.OCISpecification
	if len(spec.Process.Args) != 1 || spec.Process.Args[0] != "/hello" ||
		len(spec.Process.Env) != 1 || spec.Process.Env[0] != "PATH=/from-image" || spec.Process.Cwd != "/" {
		t.Fatalf("image command/environment not used: %+v", spec.Process)
	}
	if !spec.Root.Readonly || !spec.Process.NoNewPrivileges || len(spec.Process.Capabilities.Effective) != 0 {
		t.Fatal("image settings weakened the existing container restrictions")
	}
	for _, ns := range spec.Linux.Namespaces {
		if ns.Type == specs.NetworkNamespace {
			t.Fatal("image execution changed workload networking")
		}
	}
}

func TestOfficialHelloRegistry(t *testing.T) {
	if os.Getenv("HCSSHIM_TEST_OFFICIAL_HELLO") != "1" {
		t.Skip("set HCSSHIM_TEST_OFFICIAL_HELLO=1 for the real Docker Hub pull")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	image, err := pullOfficialHello(ctx)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("Pulled %s; /hello bytes=%d mode=%o SHA256=%x; command=%v env=%v cwd=%q",
		officialHelloReference, len(image.payload), image.mode, sha256.Sum256(image.payload),
		append(append([]string{}, image.config.Entrypoint...), image.config.Cmd...), image.config.Env, image.config.WorkingDir)
}
