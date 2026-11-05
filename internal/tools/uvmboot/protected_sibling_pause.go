//go:build windows

// Copyright (c) Microsoft Corporation. All rights reserved.

package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"golang.org/x/sys/windows"
)

// preflightProtectedSiblingPause requires both marker names to be absent,
// including dangling links. It neither creates nor deletes files. This is only
// early input validation: pause entry repeats exclusive claims after networking.
// The prefix must name a local filesystem location usable with Win32 sharing
// and delete-on-close semantics; this debugging rendezvous is not authentication.
func preflightProtectedSiblingPause(prefix string) error {
	if !filepath.IsAbs(prefix) || len(filepath.VolumeName(prefix)) != 2 {
		return errors.New("partition pause prefix must be an absolute local drive path")
	}
	for _, path := range []string{prefix + ".ready", prefix + ".resume"} {
		if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
			if err == nil {
				err = errors.New("marker already exists (including links)")
			}
			return fmt.Errorf("partition pause preflight %q: %w", path, err)
		}
	}
	return nil
}

// newProtectedPauseMarker exclusively creates a run-owned delete-on-close file.
// It returns one owned handle, or no file on failure. No delete/write sharing
// prevents replacement while held; cleanup deletes by handle, never by path.
// Readers must open with FileShare.ReadWrite|Delete because this handle owns
// write/delete access. CREATE_NEW rejects existing files and dangling links.
func newProtectedPauseMarker(path string) (*os.File, error) {
	name, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return nil, err
	}
	handle, err := windows.CreateFile(name, windows.GENERIC_READ|windows.GENERIC_WRITE|windows.DELETE,
		windows.FILE_SHARE_READ, nil, windows.CREATE_NEW,
		windows.FILE_ATTRIBUTE_NORMAL|windows.FILE_FLAG_OPEN_REPARSE_POINT|windows.FILE_FLAG_DELETE_ON_CLOSE, 0)
	if err != nil {
		return nil, fmt.Errorf("exclusively claim pause marker %q: %w", path, err)
	}
	return os.NewFile(uintptr(handle), path), nil
}

// consumeProtectedResume opens an immutable snapshot of a new resume file.
// Absence or a writer still holding the file returns false,nil for polling.
// Only an ordinary non-reparse disk file containing exactly "continue\n" is
// consumed. Invalid files remain untouched and fail the pause. A valid file is
// marked for deletion on its retained handle before close, with no path unlink
// or replacement race. A close/deletion error prevents subsequent seal calls.
func consumeProtectedResume(path string) (consumed bool, resultErr error) {
	name, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return false, err
	}
	handle, err := windows.CreateFile(name, windows.GENERIC_READ|windows.DELETE,
		windows.FILE_SHARE_READ, nil, windows.OPEN_EXISTING, windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	if errors.Is(err, windows.ERROR_FILE_NOT_FOUND) || errors.Is(err, windows.ERROR_SHARING_VIOLATION) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("open partition resume %q: %w", path, err)
	}
	file := os.NewFile(uintptr(handle), path)
	// Close the same retained object on every outcome; report close failure
	// even after consumption, rather than authorizing seals on uncertain I/O.
	defer func() {
		resultErr = errors.Join(resultErr, file.Close())
	}()
	var info windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(handle, &info); err != nil {
		return false, err
	}
	kind, err := windows.GetFileType(handle)
	if err != nil || kind != windows.FILE_TYPE_DISK ||
		info.FileAttributes&(windows.FILE_ATTRIBUTE_REPARSE_POINT|windows.FILE_ATTRIBUTE_DIRECTORY) != 0 {
		return false, errors.Join(err, errors.New("partition resume must be an ordinary non-link disk file"))
	}
	content, err := io.ReadAll(io.LimitReader(file, 10))
	if err != nil {
		return false, err
	}
	if string(content) != "continue\n" {
		return false, errors.New("partition resume must contain exactly continue followed by LF (no BOM, CR or extra bytes); file retained")
	}
	// FILE_DISPOSITION_INFO contains one BOOLEAN DeleteFile (WinBase.h).
	// No delete sharing has been granted, so validation and disposition
	// refer to the same immutable object even if the directory is renamed.
	deleteFile := byte(1)
	if err := windows.SetFileInformationByHandle(handle, windows.FileDispositionInfo, &deleteFile, 1); err != nil {
		return false, fmt.Errorf("consume partition resume by handle: %w", err)
	}
	return true, nil
}

// pausePartitionSeals publishes a fresh post-network/admission rendezvous while
// the pair's listeners, parent, VM and service watchers stay live. The serial
// caller has not committed any partition operation. It returns only after a
// fresh exact resume or error/cancellation; pause time has no operation deadline.
//
// The operator reads the complete JSON .ready using a read handle with
// FileShare.ReadWrite|Delete, then CREATE_NEW .resume with UTF-8 bytes
// "continue\n" (no BOM) and closes it. A brief exclusive .resume guard prevents
// stale creation between entry validation and readiness publication; CREATE_NEW
// may need retry until the guard closes. Never overwrite or reuse old markers.
// Only owned guard/ready and successfully consumed resume objects are deleted.
// Local filesystem/ACL correctness and debugger identity are operator concerns;
// this is not an authorization boundary or a native-in-flight cancellation API.
func (p *protectedSiblingPair) pausePartitionSeals(prefix string) (resultErr error) {
	if err := p.ctx.Err(); err != nil {
		return context.Cause(p.ctx)
	}
	if err := preflightProtectedSiblingPause(prefix); err != nil {
		return err
	}
	// Claim resume FIRST. Until ready is fully written/synced, nobody can
	// create or overwrite a resume that would be mistaken for this run's.
	guard, err := newProtectedPauseMarker(prefix + ".resume")
	if err != nil {
		return err
	}
	// Until publication succeeds the temporary resume guard remains owned;
	// every early return deletes only that exclusively created object.
	defer func() {
		if guard != nil {
			if err := guard.Close(); err != nil {
				resultErr = errors.Join(resultErr, err)
			}
		}
	}()
	ready, err := newProtectedPauseMarker(prefix + ".ready")
	if err != nil {
		return err
	}
	// Withdraw readiness on every exit by its original handle, preserving
	// cancellation identity unless an actual close error must also be joined.
	defer func() {
		if err := ready.Close(); err != nil {
			resultErr = errors.Join(resultErr, err)
		}
	}()
	type partition struct {
		Role     string `json:"role"`
		VMID     string `json:"vm_id"`
		Selected bool   `json:"selected"`
		MaskHex  string `json:"mask_hex"`
		State    string `json:"state"`
	}
	marker := struct {
		Run         string      `json:"run"`
		ReadyAt     string      `json:"ready_at_utc"`
		Lease       uint64      `json:"lease"`
		SealedPages uint64      `json:"admission_sealed_pages"`
		Resume      string      `json:"resume_exact_content"`
		Partitions  []partition `json:"partitions"`
	}{
		Run: p.run, ReadyAt: time.Now().UTC().Format(time.RFC3339Nano),
		Lease: p.memory.lease, SealedPages: p.memory.sealed, Resume: "continue\n",
	}
	for _, s := range p.seals {
		marker.Partitions = append(marker.Partitions, partition{
			Role: s.role, VMID: s.vmID, Selected: s.selected,
			MaskHex: fmt.Sprintf("%#016x", s.mask), State: s.state,
		})
	}
	content, err := json.MarshalIndent(marker, "", "  ")
	if err != nil {
		return err
	}
	content = append(content, '\n')
	if n, err := ready.Write(content); err != nil || n != len(content) {
		return errors.Join(err, errors.New("incomplete partition ready marker"))
	}
	if err := ready.Sync(); err != nil {
		return err
	}
	err = guard.Close()
	guard = nil
	if err != nil {
		return fmt.Errorf("release partition resume guard: %w", err)
	}
	fmt.Printf("protected partition pause: run=%s ready=%q at=%s; attach/stop live; create new %q containing exactly continue followed by LF\n",
		p.run, ready.Name(), marker.ReadyAt, prefix+".resume")
	tick := time.NewTicker(100 * time.Millisecond)
	defer tick.Stop()
	for {
		// VM/service/stop cancellation is sticky. Even a resume arriving
		// concurrently cannot authorize a later attempt through that gate.
		if err := p.ctx.Err(); err != nil {
			return context.Cause(p.ctx)
		}
		consumed, err := consumeProtectedResume(prefix + ".resume")
		if err != nil {
			return err
		}
		if consumed {
			fmt.Printf("protected partition resume: run=%s at=%s\n", p.run, time.Now().UTC().Format(time.RFC3339Nano))
			return nil
		}
		select {
		case <-p.ctx.Done():
			return context.Cause(p.ctx)
		case <-tick.C:
		}
	}
}
