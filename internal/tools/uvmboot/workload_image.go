//go:build windows

package main

import (
	"archive/tar"
	"bytes"
	"context"
	"debug/elf"
	"errors"
	"fmt"
	"io"
	"os"
	"path"

	"github.com/Microsoft/hcsshim/internal/guest/prot"
	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/remote"
)

// Pin the Linux/amd64 manifest, not the multi-platform index or a mutable tag.
const officialHelloReference = "docker.io/library/hello-world@sha256:d1a8d0a4eeb63aff09f5f34d4d80505e0ba81905f36158cc3970d8e07179e59e"

const helloLayerLimit = 16 * 1024 * 1024

type officialHelloImage struct {
	payload []byte
	mode    os.FileMode
	config  v1.Config
}

func (image *officialHelloImage) settings(id string) *prot.VMHostedContainerSettingsV2 {
	settings := helloSettings(id)
	settings.OCISpecification.Process.Args = append(append([]string{}, image.config.Entrypoint...), image.config.Cmd...)
	settings.OCISpecification.Process.Env = append([]string{}, image.config.Env...)
	settings.OCISpecification.Process.Cwd = image.config.WorkingDir
	if settings.OCISpecification.Process.Cwd == "" {
		settings.OCISpecification.Process.Cwd = "/"
	}
	return settings
}

func pullOfficialHello(ctx context.Context) (*officialHelloImage, error) {
	ref, err := name.NewDigest(officialHelloReference, name.StrictValidation)
	if err != nil {
		return nil, err
	}
	image, err := remote.Image(ref, remote.WithContext(ctx),
		remote.WithPlatform(v1.Platform{OS: "linux", Architecture: "amd64"}))
	if err != nil {
		return nil, fmt.Errorf("pull official hello-world (host Internet access required): %w", err)
	}
	digest, err := image.Digest()
	if err != nil {
		return nil, err
	}
	if digest.String() != ref.DigestStr() {
		return nil, errors.New("official hello-world manifest digest mismatch")
	}
	return readOfficialHello(image)
}

func readOfficialHello(image v1.Image) (*officialHelloImage, error) {
	config, err := image.ConfigFile()
	if err != nil {
		return nil, fmt.Errorf("read official hello-world configuration: %w", err)
	}
	args := append(append([]string{}, config.Config.Entrypoint...), config.Config.Cmd...)
	if config.OS != "linux" || config.Architecture != "amd64" ||
		len(args) != 1 || args[0] != "/hello" ||
		(config.Config.WorkingDir != "" && config.Config.WorkingDir != "/") ||
		(config.Config.User != "" && config.Config.User != "0" && config.Config.User != "0:0") ||
		len(config.Config.Volumes) != 0 || config.Config.Tty {
		return nil, errors.New("unsupported official hello-world configuration; expected Linux/amd64 /hello with root user and working directory /")
	}
	layers, err := image.Layers()
	if err != nil {
		return nil, err
	}
	if len(layers) != 1 || config.RootFS.Type != "layers" || len(config.RootFS.DiffIDs) != 1 {
		return nil, errors.New("expected the official hello-world single-layer scratch image")
	}
	stream, err := layers[0].Uncompressed()
	if err != nil {
		return nil, fmt.Errorf("download official hello-world layer: %w", err)
	}
	data, readErr := io.ReadAll(io.LimitReader(stream, helloLayerLimit+1))
	if err := errors.Join(readErr, stream.Close()); err != nil {
		return nil, fmt.Errorf("read official hello-world layer: %w", err)
	}
	if len(data) > helloLayerLimit {
		return nil, errors.New("official hello-world layer exceeds 16 MiB")
	}
	diffID, _, err := v1.SHA256(bytes.NewReader(data))
	if err != nil {
		return nil, err
	}
	if diffID != config.RootFS.DiffIDs[0] {
		return nil, errors.New("official hello-world uncompressed layer digest mismatch")
	}
	payload, mode, err := unpackOfficialHello(data)
	if err != nil {
		return nil, err
	}
	return &officialHelloImage{payload: payload, mode: mode, config: config.Config}, nil
}

func unpackOfficialHello(data []byte) ([]byte, os.FileMode, error) {
	archive := tar.NewReader(bytes.NewReader(data))
	var payload []byte
	var mode os.FileMode
	for {
		header, err := archive.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, 0, fmt.Errorf("read official hello-world rootfs: %w", err)
		}
		if (header.Name == "." || header.Name == "./") && header.Typeflag == tar.TypeDir {
			continue
		}
		// This command supports the official scratch image, not arbitrary tar
		// extraction, links, whiteouts, devices or multi-layer filesystems.
		if path.Clean(header.Name) != "hello" || (header.Name != "hello" && header.Name != "./hello") ||
			header.Typeflag != tar.TypeReg || payload != nil ||
			header.Size <= 0 || header.Size > helloLayerLimit ||
			header.Mode&^0777 != 0 || header.Mode&0111 == 0 || header.Uid != 0 || header.Gid != 0 {
			return nil, 0, fmt.Errorf("unsupported official hello-world rootfs entry %q", header.Name)
		}
		payload, err = io.ReadAll(archive)
		if err != nil {
			return nil, 0, err
		}
		mode = os.FileMode(header.Mode)
	}
	if len(payload) == 0 {
		return nil, 0, errors.New("official hello-world image has no /hello executable")
	}
	binary, err := elf.NewFile(bytes.NewReader(payload))
	if err != nil {
		return nil, 0, fmt.Errorf("official /hello is not an ELF executable: %w", err)
	}
	defer binary.Close()
	if binary.Machine != elf.EM_X86_64 || binary.Class != elf.ELFCLASS64 {
		return nil, 0, errors.New("official /hello must be Linux amd64")
	}
	for _, program := range binary.Progs {
		if program.Type == elf.PT_INTERP {
			return nil, 0, errors.New("official scratch image /hello must be statically linked")
		}
	}
	return payload, mode, nil
}
