//go:build windows

package scsi

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"sync"
	"time"
)

// SiblingExportControl controls exports in the diode, not devices in the workload.
// Remove must confirm withdrawal (or absence) before returning success.
type SiblingExportControl interface {
	Add(ctx context.Context, controller, lun uint, exportLUN uint8, token uint64, readOnly bool) error
	Remove(ctx context.Context, exportLUN uint8, token uint64) error
}

type siblingAttachment struct {
	mount     *Mount
	token     uint64
	withdrawn bool
	uncertain error
}

type siblingHostBackend struct {
	diode     *Manager
	diodeID   string
	control   SiblingExportControl
	mu        sync.Mutex
	disks     map[uint]*siblingAttachment
	protected bool // Immutable after pre-task EnableProtectedSibling.
	// The existing attach manager serializes each LUN's removal. Final
	// protected drainage runs only after the full manager-operation fence.
}

// NewSiblingHostBackend keeps RP attachments on the diode while exporting the
// workload manager's logical LUNs over its existing sibling controller.
func NewSiblingHostBackend(diode *Manager, diodeID string, control SiblingExportControl) (HostBackend, error) {
	if diode == nil || diodeID == "" || control == nil {
		return nil, errors.New("sibling storage requires diode manager, VM ID and export control")
	}
	return &siblingHostBackend{
		diode: diode, diodeID: diodeID, control: control,
		disks: make(map[uint]*siblingAttachment),
	}, nil
}

// ConfigureSibling is a pre-task operation; existing attachments may not be migrated.
func (m *Manager) ConfigureSibling(backend HostBackend, guest GuestBackend) error {
	if m == nil || guest == nil {
		return ErrNotInitialized
	}
	if _, ok := backend.(*siblingHostBackend); !ok {
		return errors.New("sibling storage requires a diode-backed host backend")
	}
	am, mm := m.attachManager, m.mountManager
	am.m.Lock()
	defer am.m.Unlock()
	mm.m.Lock()
	defer mm.m.Unlock()
	if _, configured := am.attacher.(*siblingHostBackend); configured {
		return errors.New("sibling storage is already configured")
	}
	for _, controller := range am.slots {
		for _, attachment := range controller {
			if attachment != nil && attachment.config != nil {
				return errors.New("cannot configure sibling storage after disk attachment")
			}
		}
	}
	for _, mount := range mm.mounts {
		if mount != nil {
			return errors.New("cannot configure sibling storage after guest mount")
		}
	}
	m.attachManager = newAttachManager(backend, guest, 1, 64, []Slot{{Controller: 0, LUN: 0}})
	m.mountManager = newMountManager(guest, mm.mountFmt)
	return nil
}

func (b *siblingHostBackend) attach(ctx context.Context, controller, lun uint, config *attachConfig) (err error) {
	if controller != 0 || lun == 0 || lun >= 255 || config.typ != "VirtualDisk" {
		return errors.New("sibling storage requires a virtual disk on controller 0, LUN 1..254")
	}
	var bytes [8]byte
	var token uint64
	for token == 0 {
		if _, err := rand.Read(bytes[:]); err != nil {
			return fmt.Errorf("generate sibling export token: %w", err)
		}
		token = binary.LittleEndian.Uint64(bytes[:])
	}
	attachment := &siblingAttachment{token: token}
	b.mu.Lock()
	if _, exists := b.disks[lun]; exists {
		b.mu.Unlock()
		return fmt.Errorf("sibling LUN %d still has an unresolved attachment", lun)
	}
	b.disks[lun] = attachment
	b.mu.Unlock()

	attachment.mount, err = b.diode.AddVirtualDisk(ctx, config.path, config.readOnly, b.diodeID, "", nil)
	if err != nil {
		if b.protected {
			attachment.uncertain = err
			return fmt.Errorf("diode attachment uncertain; retained: %w", err)
		}
		b.mu.Lock()
		delete(b.disks, lun)
		b.mu.Unlock()
		return fmt.Errorf("attach disk to diode: %w", err)
	}
	err = b.control.Add(ctx, attachment.mount.Controller(), attachment.mount.LUN(), uint8(lun), token, config.readOnly)
	if err == nil {
		return nil
	}
	// A cancelled reply does not prove that the diode did not publish the disk.
	cleanupCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 35*time.Second)
	defer cancel()
	return errors.Join(err, b.detach(cleanupCtx, controller, lun))
}

func (b *siblingHostBackend) detach(ctx context.Context, controller, lun uint) error {
	if controller != 0 || lun == 0 || lun >= 255 {
		return errors.New("invalid sibling export location")
	}
	b.mu.Lock()
	attachment, exists := b.disks[lun]
	b.mu.Unlock()
	if !exists {
		return fmt.Errorf("sibling LUN %d has no tracked attachment", lun)
	}
	if attachment.uncertain != nil || attachment.mount == nil {
		return errors.Join(errors.New("sibling attachment ownership is unknown"), attachment.uncertain)
	}
	if !attachment.withdrawn {
		if err := b.control.Remove(ctx, uint8(lun), attachment.token); err != nil {
			return fmt.Errorf("withdraw sibling LUN %d; diode backing retained: %w", lun, err)
		}
		attachment.withdrawn = true
	}
	if err := attachment.mount.Release(ctx); err != nil {
		return fmt.Errorf("release diode backing for LUN %d: %w", lun, err)
	}
	b.mu.Lock()
	delete(b.disks, lun)
	b.mu.Unlock()
	return nil
}

func (b *siblingHostBackend) beforeUnplug(ctx context.Context, controller, lun uint) error {
	b.mu.Lock()
	attachment, exists := b.disks[lun]
	b.mu.Unlock()
	if controller != 0 || !exists {
		return fmt.Errorf("invalid sibling unplug location %d:%d", controller, lun)
	}
	if !attachment.withdrawn {
		if err := b.control.Remove(ctx, uint8(lun), attachment.token); err != nil {
			return fmt.Errorf("withdraw sibling LUN %d before guest unplug: %w", lun, err)
		}
		attachment.withdrawn = true
	}
	return nil
}

// protectedSiblingOperations fences complete manager operations, not just host
// callbacks. Rollback and guest mounting stay inside the admitted operation.
type protectedSiblingOperations struct {
	mu         sync.Mutex
	closing    bool
	operations sync.WaitGroup
}

// begin rejects all work after final storage drainage begins.
func (g *protectedSiblingOperations) begin() error {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.closing {
		return errors.New("protected sibling storage is closing")
	}
	g.operations.Add(1)
	return nil
}

// EnableProtectedSibling opts into retained failures and full-operation joins.
// Call once after ConfigureSibling, before admitting any task.
func (m *Manager) EnableProtectedSibling() error {
	b, ok := m.attachManager.attacher.(*siblingHostBackend)
	if !ok || m.protected != nil {
		return errors.New("protected storage requires a fresh sibling manager")
	}
	b.protected = true
	m.protected = &protectedSiblingOperations{}
	return nil
}

// CloseProtectedSibling joins full operations and withdraws residual exports
// using their real diode mounts. The pair first drains tasks and observes workload
// exit; diode GCS must remain alive. Failed records are not discarded or replayed.
func (m *Manager) CloseProtectedSibling(ctx context.Context) error {
	if m.protected == nil {
		return errors.New("protected sibling storage was not enabled")
	}
	g := m.protected
	g.mu.Lock()
	g.closing = true
	g.mu.Unlock()
	g.operations.Wait()
	b := m.attachManager.attacher.(*siblingHostBackend)
	b.mu.Lock()
	luns := make([]uint, 0, len(b.disks))
	for lun := range b.disks {
		luns = append(luns, lun)
	}
	b.mu.Unlock()
	var result error
	for _, lun := range luns {
		result = errors.Join(result, b.detach(ctx, 0, lun))
	}
	return result
}
