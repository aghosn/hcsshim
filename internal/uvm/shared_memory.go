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

// ValidateProtectedSharedOperationResult checks a compact cached v2 receipt,
// local owner flags and retained lease/page identity. It never queries native
// state. A failed HRESULT/status is an error alongside the preserved receipt;
// missing native validity is not zero progress or release authorization.
// Install/Remove legitimately have only HRESULT/local ownership outcomes.
func ValidateProtectedSharedOperationResult(p *hcsschema.ProtectedSharedRegionInfo, lease, pages uint64) error {
	if p == nil || p.Version != 2 || p.LeaseId == 0 || p.PageCount == 0 ||
		(lease != 0 && p.LeaseId != lease) || p.PageCount != pages ||
		p.InitializedPages > pages ||
		p.PagesProcessed > 4 || uint64(p.PagesProcessed) > pages ||
		(!p.OperationResultValid && (p.PagesProcessed != 0 || p.OperationStatus != 0)) ||
		(p.Removed && (p.Prepared || p.Installed)) || (p.Installed && !p.Prepared) {
		return fmt.Errorf("malformed or mismatched protected operation receipt")
	}
	if p.OperationHresult&0x80000000 != 0 ||
		(p.OperationResultValid && p.OperationStatus&0x80000000 != 0) {
		return fmt.Errorf("protected action failed: HRESULT=%#08x native-valid=%t status=%#08x processed=%d",
			p.OperationHresult, p.OperationResultValid, p.OperationStatus, p.PagesProcessed)
	}
	return nil
}

// ProtectedSharedOperationResult reads only the worker's cached last receipt,
// with ordinary SectionName/GPA properties. No native lifecycle/query occurs.
// Callers serialize actions and receipt reads; this is not live page state.
// Missing, mismatched or failed receipts return errors, never zero progress.
func (uvm *UtilityVM) ProtectedSharedOperationResult(ctx context.Context, region hcsschema.SharedMemoryRegion) (*hcsschema.ProtectedSharedRegionInfo, error) {
	if err := ValidateProtectedSharedRegion(region); err != nil {
		return nil, err
	}
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
	return p, ValidateProtectedSharedOperationResult(p, region.ProtectedSharedLeaseId, uint64(region.Length)/4096)
}

// ModifyProtectedShared checks a private action and borrows the controller
// capability through HCS completion. Returns the cached receipt even on action
// failure, joining real action failure with independent read/validation errors.
// Unframed work is never zero progress. After cancellation, receipt reading has
// a separate five-second budget; it dispatches no further lifecycle operation.
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
	case hcsschema.ProtectedSharedInitialize, hcsschema.ProtectedSharedSeal,
		hcsschema.ProtectedSharedBeginTeardown, hcsschema.ProtectedSharedReclaim:
		if region.ProtectedSharedLeaseId == 0 || region.ProtectedSharedPageCount == 0 ||
			region.ProtectedSharedPageCount > 4 || region.ProtectedSharedPageIndex >= pages ||
			uint64(region.ProtectedSharedPageCount) > pages-region.ProtectedSharedPageIndex ||
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
	// properties read or turning an invalid frame into a success receipt.
	queryCtx := ctx
	if ctx.Err() != nil {
		var cancel context.CancelFunc
		queryCtx, cancel = context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		defer cancel()
	}
	p, queryErr := uvm.ProtectedSharedOperationResult(queryCtx, region)
	if queryErr == nil {
		switch region.ProtectedSharedOperation {
		case hcsschema.ProtectedSharedInstall:
			if p.OperationResultValid || !p.Installed || !p.Prepared || p.Removed {
				queryErr = errors.New("missing actual installation ownership receipt")
			}
		case hcsschema.ProtectedSharedRemove:
			if p.OperationResultValid || !p.Removed {
				queryErr = errors.New("missing actual removal ownership receipt")
			}
		case "", hcsschema.ProtectedSharedNone:
			if !p.OperationResultValid || !p.Prepared || p.Installed || p.Removed ||
				p.PagesProcessed != 0 || p.InitializedPages != 0 {
				queryErr = errors.New("missing native preparation receipt")
			}
		default:
			if !p.OperationResultValid || p.PagesProcessed != region.ProtectedSharedPageCount {
				queryErr = errors.New("missing complete native operation receipt")
			}
		}
	}
	return p, errors.Join(err, queryErr)
}
