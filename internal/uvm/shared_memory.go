//go:build windows

package uvm

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"syscall"
	"time"

	"github.com/Microsoft/hcsshim/internal/computecore"
	"github.com/Microsoft/hcsshim/internal/hcs"
	"github.com/Microsoft/hcsshim/internal/hcs/resourcepaths"
	hcsschema "github.com/Microsoft/hcsshim/internal/hcs/schema2"
	hcsv2 "github.com/Microsoft/hcsshim/internal/hcs/v2"
)

const sharedMemoryRegionProperty = "SharedMemoryRegion"

// SharedMemoryRegions returns the configured shared-memory mappings for the
// utility VM.
func (uvm *UtilityVM) SharedMemoryRegions(ctx context.Context) ([]hcsschema.SharedMemoryRegionInfo, error) {
	if uvm.hcsSystem == nil {
		return nil, fmt.Errorf("utility VM has no HCS compute system")
	}

	props, err := uvm.hcsSystem.PropertiesV2(ctx, hcsschema.PTSharedMemoryRegion)
	if err == nil {
		return props.SharedMemoryRegionInfo, nil
	}
	if !errors.Is(err, hcs.ErrElementNotFound) {
		return nil, fmt.Errorf("query shared-memory regions: %w", err)
	}

	props, queryErr := uvm.hcsSystem.PropertiesV3(
		ctx,
		&hcsschema.PropertyQuery{
			Queries: map[string]interface{}{
				sharedMemoryRegionProperty: nil,
			},
		},
	)
	if queryErr != nil {
		return nil, fmt.Errorf(
			"query shared-memory regions with legacy and named properties: "+
				"legacy: %v; named: %w",
			err,
			queryErr,
		)
	}
	if len(props.SharedMemoryRegionInfo) > 0 {
		return props.SharedMemoryRegionInfo, nil
	}

	response, ok := props.PropertyResponses[sharedMemoryRegionProperty]
	if !ok || len(response.Response) == 0 {
		return nil, fmt.Errorf(
			"named shared-memory property returned no response",
		)
	}

	regions, parseErr := parseSharedMemoryRegionResponse(response.Response)
	if parseErr != nil {
		return nil, fmt.Errorf(
			"decode named shared-memory property response %s: %w",
			response.Response,
			parseErr,
		)
	}
	return regions, nil
}

// parseSharedMemoryRegionResponse decodes the named property's array or either
// legacy wrapper without publishing partial regions on error. Private frames
// use their required-field decoder in every shape; a malformed array must not
// lose its private error/progress diagnostics through a wrapper retry. Ordinary
// null/empty arrays and optional legacy region fields retain their behavior.
func parseSharedMemoryRegionResponse(
	response json.RawMessage,
) ([]hcsschema.SharedMemoryRegionInfo, error) {
	trimmed := bytes.TrimSpace(response)
	if (len(trimmed) != 0 && trimmed[0] == '[') || bytes.Equal(trimmed, []byte("null")) {
		var regions []hcsschema.SharedMemoryRegionInfo
		if err := json.Unmarshal(response, &regions); err != nil {
			return nil, fmt.Errorf("decode shared-memory region array %s: %w", response, err)
		}
		return regions, nil
	}

	var wrapped struct {
		SharedMemoryRegionInfo []hcsschema.SharedMemoryRegionInfo `json:"SharedMemoryRegionInfo"`
		Regions                []hcsschema.SharedMemoryRegionInfo `json:"Regions"`
	}
	if err := json.Unmarshal(response, &wrapped); err != nil {
		return nil, err
	}
	if len(wrapped.SharedMemoryRegionInfo) > 0 {
		return wrapped.SharedMemoryRegionInfo, nil
	}
	if len(wrapped.Regions) > 0 {
		return wrapped.Regions, nil
	}
	return nil, fmt.Errorf("response contains no shared-memory regions")
}

// SharedMemoryByteGPA converts the historical signed page index to bytes.
// Negative indices, nonpositive/unaligned byte lengths and address overflow
// fail before arithmetic. Zero GPA is valid; this does not imply installation.
func SharedMemoryByteGPA(page int64, length int64) (uint64, error) {
	if page < 0 || length <= 0 || length%4096 != 0 ||
		uint64(page) > math.MaxUint64>>12 {
		return 0, fmt.Errorf("invalid shared-memory page/length: %d/%d", page, length)
	}
	address := uint64(page) << 12
	if uint64(length) > math.MaxUint64-address {
		return 0, fmt.Errorf("shared-memory byte range overflows")
	}
	return address, nil
}

// ValidateProtectedSharedRegion checks immutable private settings before
// converting signed byte ranges. Authority comes only from a file capability.
func ValidateProtectedSharedRegion(r hcsschema.SharedMemoryRegion) error {
	if !r.ProtectedShared || r.SectionName == "" || r.ProtectedSharedControllerUri == "" ||
		r.StartOffset < 0 || r.StartOffset%4096 != 0 || r.Length <= 0 || r.Length%4096 != 0 {
		return fmt.Errorf("invalid protected shared-memory configuration")
	}
	if uint64(r.StartOffset)+uint64(r.Length) > math.MaxInt64 {
		return fmt.Errorf("protected section range overflows")
	}
	return nil
}

// validateProtectedSharedOptions requires matching borrowed file capabilities
// for hidden preparation. Ordinary configurations remain resource-free.
func validateProtectedSharedOptions(opts *OptionsLCOW) error {
	for _, r := range opts.SharedMemoryRegions {
		if !r.ProtectedShared {
			if r.ProtectedSharedControllerUri != "" || r.ProtectedSharedOperation != "" ||
				r.ProtectedSharedLeaseId != 0 || r.ProtectedSharedLifetimeId != 0 ||
				r.ProtectedSharedPageIndex != 0 || r.ProtectedSharedPageCount != 0 {
				return fmt.Errorf("private shared-memory fields without opt-in")
			}
			continue
		}
		if err := ValidateProtectedSharedRegion(r); err != nil {
			return err
		}
		if !r.HiddenFromGuest ||
			(r.ProtectedSharedOperation != "" && r.ProtectedSharedOperation != hcsschema.ProtectedSharedNone) ||
			r.ProtectedSharedLeaseId != 0 || r.ProtectedSharedLifetimeId != 0 ||
			r.ProtectedSharedPageIndex != 0 || r.ProtectedSharedPageCount != 0 {
			return fmt.Errorf("protected creation must be hidden preparation only")
		}
		found := 0
		for _, resource := range opts.ProtectedSharedResources {
			if resource.URI == r.ProtectedSharedControllerUri && resource.Type == computecore.HcsResourceTypeFile &&
				resource.Handle != 0 && resource.Handle != syscall.InvalidHandle {
				found++
			}
		}
		if found != 1 {
			return fmt.Errorf("protected preparation requires exactly one controller capability")
		}
	}
	return nil
}

// ErrProtectedSharedPageUnavailable classifies a framed STATUS_NOT_FOUND query.
// Explicit reclaim produces this result, but a stale lease/lifetime can too.
// It is not success or proof of reclamation without a separately validated action
// receipt. The caller retains the raw response and its independent action prefix.
var ErrProtectedSharedPageUnavailable = errors.New("protected page unavailable (reclaimed or stale identity)")

// ValidateProtectedSharedInfo checks framing and bounded per-page identities.
// Failed operations retain unsigned status/prefix fields. requireSnapshot rejects
// prepared-only, stale and incomplete output rather than falling back to legacy.
// A missing snapshot is valid only for a successfully queried, uninitialized
// cursor. Nested query failures propagate even if the outer properties call and
// preceding action succeeded; action failures do not invalidate a good snapshot.
func ValidateProtectedSharedInfo(p *hcsschema.ProtectedSharedRegionInfo, lease, pages, index, lifetime uint64, requireSnapshot bool) error {
	if p == nil || p.Version != 1 || p.LeaseId == 0 || p.PageCount == 0 ||
		(lease != 0 && p.LeaseId != lease) || p.PageCount != pages ||
		p.PageIndex != index || index >= pages || p.InitializedPages > pages ||
		p.PagesProcessed > 4 || uint64(p.PagesProcessed) > pages ||
		(!p.OperationResultValid && p.PagesProcessed != 0) ||
		p.LastMapPagesProcessed > pages || (p.Removed && (p.Prepared || p.Installed)) {
		return fmt.Errorf("malformed or stale protected region metadata")
	}
	if !p.SnapshotValid {
		if !p.QueryResultValid {
			return fmt.Errorf("unframed protected metadata query")
		}
		if p.QueryHresult != 0 || p.QueryStatus != 0 {
			// VsmmProtectedSharedControlIoctl returns STATUS_NOT_FOUND for a
			// reclaimed page or stale identity. Never conflate it with the
			// successful, snapshot-free query of an uninitialized page.
			if p.QueryStatus == 0xc0000225 && p.QueryHresult&0x80000000 != 0 {
				return ErrProtectedSharedPageUnavailable
			}
			return fmt.Errorf("protected metadata query failed: HRESULT=%#08x status=%#08x", p.QueryHresult, p.QueryStatus)
		}
		if requireSnapshot || p.Complete || p.RegionComplete {
			return fmt.Errorf("incomplete protected page snapshot")
		}
		if index < p.InitializedPages || p.Installed || p.LifetimeId != 0 ||
			len(p.Registrations) != 0 || p.NextPageIndex != 0 {
			return fmt.Errorf("missing snapshot for an initialized protected page")
		}
		return nil
	}
	if !p.QueryResultValid || p.QueryHresult != 0 || p.QueryStatus != 0 ||
		!p.Complete || p.NextPageIndex != index+1 ||
		p.RegionComplete != (pages == 1 && index == 0) ||
		p.LifetimeId == 0 || p.LifetimeId >= math.MaxInt64 ||
		(lifetime != 0 && lifetime != p.LifetimeId) || p.SpaPage > math.MaxUint64>>12 ||
		p.State > 3 || p.Initialization > 2 || p.RootProtection > 2 || p.Reclaim > 4 ||
		p.PageType != 1 || p.PageOwnership != 0 || len(p.Registrations) > 64 {
		return fmt.Errorf("invalid protected snapshot frame/state/identity")
	}
	seen := make(map[uint64]bool)
	for _, r := range p.Registrations {
		if r.RegistrationId == 0 || r.RegistrationId >= math.MaxInt64 ||
			r.PartitionId == 0 || r.PartitionId >= math.MaxInt64 || r.GpaPage >= 1<<40 ||
			r.Vtl != 0 || r.SharePermission & ^uint32(7) != 0 ||
			r.State > 3 || r.RemovalReason > 4 ||
			((r.State < 2) != (r.RemovalReason == 0)) || seen[r.RegistrationId] {
			return fmt.Errorf("invalid or duplicate protected registration")
		}
		seen[r.RegistrationId] = true
	}
	return nil
}

// ProtectedSharedInfo reads exactly the configured private region, failing if
// only a legacy response is available. Callers serialize cursor/lifecycle updates;
// peers may still advance controller-wide LastMap. Invalid metadata returns an
// error alongside the untrusted frame for diagnosis, not permission to use it.
func (uvm *UtilityVM) ProtectedSharedInfo(ctx context.Context, region hcsschema.SharedMemoryRegion, index, lifetime uint64, requireSnapshot bool) (*hcsschema.ProtectedSharedRegionInfo, error) {
	regions, err := uvm.SharedMemoryRegions(ctx)
	if err != nil {
		return nil, err
	}
	var found *hcsschema.SharedMemoryRegionInfo
	for i := range regions {
		if regions[i].SectionName == region.SectionName {
			if found != nil {
				return nil, fmt.Errorf("duplicate protected region response")
			}
			found = &regions[i]
		}
	}
	if found == nil {
		return nil, fmt.Errorf("missing protected region response")
	}
	if _, err := SharedMemoryByteGPA(int64(found.GuestPhysicalAddress), int64(region.Length)); err != nil {
		return nil, err
	}
	p := found.ProtectedShared
	return p, ValidateProtectedSharedInfo(p, region.ProtectedSharedLeaseId, uint64(region.Length)/4096, index, lifetime, requireSnapshot)
}

// ModifyProtectedShared checks a private action and borrows the controller
// capability through HCS completion. It returns subsequent diagnostics even on
// failure. Unframed/invalid output is unknown work, never zero progress. After
// cancellation a separate five-second query budget preserves failure evidence.
func (uvm *UtilityVM) ModifyProtectedShared(ctx context.Context, region hcsschema.SharedMemoryRegion, resource hcsv2.OperationResource) (*hcsschema.ProtectedSharedRegionInfo, error) {
	if err := ValidateProtectedSharedRegion(region); err != nil {
		return nil, err
	}
	if resource.URI != region.ProtectedSharedControllerUri || resource.Type != computecore.HcsResourceTypeFile {
		return nil, fmt.Errorf("protected operation controller mismatch")
	}
	pages := uint64(region.Length) / 4096
	switch region.ProtectedSharedOperation {
	case "", hcsschema.ProtectedSharedNone:
		if !region.HiddenFromGuest || region.ProtectedSharedLeaseId != 0 ||
			region.ProtectedSharedLifetimeId != 0 || region.ProtectedSharedPageIndex != 0 ||
			region.ProtectedSharedPageCount != 0 {
			return nil, fmt.Errorf("invalid protected preparation request")
		}
	case hcsschema.ProtectedSharedInstall, hcsschema.ProtectedSharedRemove:
		if region.ProtectedSharedLeaseId == 0 || region.ProtectedSharedLifetimeId != 0 ||
			region.ProtectedSharedPageIndex != 0 || region.ProtectedSharedPageCount != 0 ||
			(region.ProtectedSharedOperation == hcsschema.ProtectedSharedInstall && region.HiddenFromGuest) {
			return nil, fmt.Errorf("invalid protected installation/removal request")
		}
	case hcsschema.ProtectedSharedInitialize, hcsschema.ProtectedSharedSeal, hcsschema.ProtectedSharedQuery,
		hcsschema.ProtectedSharedBeginTeardown, hcsschema.ProtectedSharedReclaim:
		if region.ProtectedSharedLeaseId == 0 || region.ProtectedSharedPageCount == 0 ||
			region.ProtectedSharedPageCount > 4 || region.ProtectedSharedPageIndex >= pages ||
			uint64(region.ProtectedSharedPageCount) > pages-region.ProtectedSharedPageIndex ||
			(region.ProtectedSharedOperation == hcsschema.ProtectedSharedQuery && region.ProtectedSharedPageCount != 1) ||
			(region.ProtectedSharedOperation == hcsschema.ProtectedSharedInitialize && region.ProtectedSharedLifetimeId != 0) {
			return nil, fmt.Errorf("invalid protected control range/identity")
		}
	default:
		return nil, fmt.Errorf("unsupported protected shared-memory action")
	}
	if uvm.hcsSystem == nil {
		return nil, fmt.Errorf("protected operation has no compute system")
	}
	err := uvm.hcsSystem.ModifyWithResources(ctx, &hcsschema.ModifySettingRequest{
		ResourcePath: resourcepaths.SharedMemoryRegionResourcePath,
		RequestType:  "Update",
		Settings:     region,
	}, []hcsv2.OperationResource{resource})
	// Preserve diagnostics after a cancelled action without using an unbounded
	// background query or turning an invalid frame into a success receipt.
	queryCtx := ctx
	if ctx.Err() != nil {
		var cancel context.CancelFunc
		queryCtx, cancel = context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		defer cancel()
	}
	p, queryErr := uvm.ProtectedSharedInfo(queryCtx, region, region.ProtectedSharedPageIndex, region.ProtectedSharedLifetimeId, false)
	return p, errors.Join(err, queryErr)
}

// CollectProtectedShared returns independently coherent page snapshots within
// a required deadline. Failure returns only the collected prefix; nil error
// means all pages, never region atomicity. Duplicate or stale identities fail.
func (uvm *UtilityVM) CollectProtectedShared(ctx context.Context, region hcsschema.SharedMemoryRegion, resource hcsv2.OperationResource, lifetimes []uint64) ([]hcsschema.ProtectedSharedRegionInfo, error) {
	if _, ok := ctx.Deadline(); !ok {
		return nil, fmt.Errorf("protected collection requires a deadline")
	}
	if err := ValidateProtectedSharedRegion(region); err != nil {
		return nil, err
	}
	pages := uint64(region.Length) / 4096
	if uint64(len(lifetimes)) != pages {
		return nil, fmt.Errorf("protected collection identity count mismatch")
	}
	var result []hcsschema.ProtectedSharedRegionInfo
	seenSPAs := make(map[uint64]bool)
	seenLifetimes := make(map[uint64]bool)
	for index, lifetime := range lifetimes {
		if err := ctx.Err(); err != nil {
			return result, err
		}
		region.ProtectedSharedOperation = hcsschema.ProtectedSharedQuery
		region.ProtectedSharedPageIndex = uint64(index)
		region.ProtectedSharedPageCount = 1
		region.ProtectedSharedLifetimeId = lifetime
		p, err := uvm.ModifyProtectedShared(ctx, region, resource)
		if err == nil {
			err = ValidateProtectedSharedInfo(p, region.ProtectedSharedLeaseId, pages, uint64(index), lifetime, true)
		}
		if err != nil {
			return result, err
		}
		if seenSPAs[p.SpaPage] || seenLifetimes[p.LifetimeId] {
			return result, fmt.Errorf("duplicate page identity in protected collection")
		}
		seenSPAs[p.SpaPage], seenLifetimes[p.LifetimeId] = true, true
		result = append(result, *p)
	}
	return result, nil
}
