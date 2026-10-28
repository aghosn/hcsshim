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
// pages counts 4-KiB pages; lease zero permits retained-lease discovery.
// Install/Remove legitimately have only HRESULT/local ownership outcomes.
// The caller owns p and serializes access; validation does not change it.
func ValidateProtectedSharedOperationResult(p *hcsschema.ProtectedSharedRegionInfo, lease, pages uint64) error {
	if err := ValidateProtectedSharedOperationResultStructure(p, lease, pages); err != nil {
		return err
	}
	return validateProtectedSharedOperationStatus(p)
}

// ValidateProtectedSharedOperationResultStructure checks compact v2 framing,
// local owner consistency and lease/page identity without judging action success.
// pages counts 4-KiB pages; lease zero permits discovery of the retained lease.
// It reads caller-owned cached data only, not live native state. A nil error
// does not authorize release or imply that the reported action succeeded.
func ValidateProtectedSharedOperationResultStructure(p *hcsschema.ProtectedSharedRegionInfo, lease, pages uint64) error {
	if p == nil || p.Version != 2 || p.LeaseId == 0 || p.PageCount == 0 ||
		(lease != 0 && p.LeaseId != lease) || p.PageCount != pages ||
		p.InitializedPages > pages ||
		p.PagesProcessed > 4 || uint64(p.PagesProcessed) > pages ||
		(!p.OperationResultValid && (p.PagesProcessed != 0 || p.OperationStatus != 0)) ||
		(p.Removed && (p.Prepared || p.Installed)) || (p.Installed && !p.Prepared) {
		return fmt.Errorf("malformed or mismatched protected operation receipt")
	}
	return nil
}

// validateProtectedSharedOperationStatus rejects failed HRESULT/native status
// while preserving the original diagnostics. p must already be structurally
// validated; this reads cached status only and neither dispatches nor owns work.
func validateProtectedSharedOperationStatus(p *hcsschema.ProtectedSharedRegionInfo) error {
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
// region.Length is bytes and its optional lease must match when nonzero.
// The returned receipt remains available on status/structural failure.
func (uvm *UtilityVM) ProtectedSharedOperationResult(ctx context.Context, region hcsschema.SharedMemoryRegion) (*hcsschema.ProtectedSharedRegionInfo, error) {
	p, err := uvm.protectedSharedOperationReceipt(ctx, region)
	if err == nil {
		err = validateProtectedSharedOperationStatus(p)
	}
	return p, err
}

// protectedSharedOperationReceipt reads and structurally validates the cached
// receipt for the region's section and lease, with Length in bytes. The caller
// serializes actions and reads; returned data is not a live native observation.
// Query/decode/identity errors remain separate from the cached action status,
// and a returned malformed receipt must not be treated as validated progress.
func (uvm *UtilityVM) protectedSharedOperationReceipt(ctx context.Context, region hcsschema.SharedMemoryRegion) (*hcsschema.ProtectedSharedRegionInfo, error) {
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
	return p, ValidateProtectedSharedOperationResultStructure(p, region.ProtectedSharedLeaseId, uint64(region.Length)/4096)
}

// ProtectedSharedModifyOutcome separates an attempted HCS action from its
// independent cached receipt observation. Dispatched means the validated request
// was submitted to HCS ModifyWithResources, not proof of native execution.
// ActionError includes preflight/submission/completion failure. ReceiptError
// covers only acquisition, decoding and structural validation, never a failed
// cached HRESULT. Receipt may be nonnil on either failure; flags must be retained
// conservatively for cleanup. Counts are 4-KiB pages, not live page inventory.
type ProtectedSharedModifyOutcome struct {
	Dispatched   bool
	ActionError  error
	Receipt      *hcsschema.ProtectedSharedRegionInfo
	ReceiptError error
}

// validateProtectedSharedModify checks region identity, byte/page bounds and
// borrowed controller identity before submission. It neither dispatches work
// nor transfers resource ownership; the capability must survive HCS completion.
func validateProtectedSharedModify(region hcsschema.SharedMemoryRegion, resource hcsv2.OperationResource) error {
	if err := ValidateProtectedSharedRegion(region); err != nil {
		return err
	}
	if resource.URI != region.ProtectedSharedControllerUri || resource.Type != computecore.HcsResourceTypeFile {
		return fmt.Errorf("protected operation controller mismatch")
	}
	pages := uint64(region.Length) / 4096
	switch region.ProtectedSharedOperation {
	case "", hcsschema.ProtectedSharedNone:
		if !region.HiddenFromGuest || region.ProtectedSharedLeaseId != 0 ||
			region.ProtectedSharedLifetimeId != 0 || region.ProtectedSharedPageIndex != 0 ||
			region.ProtectedSharedPageCount != 0 {
			return fmt.Errorf("invalid protected preparation request")
		}
	case hcsschema.ProtectedSharedInstall, hcsschema.ProtectedSharedRemove:
		if region.ProtectedSharedLeaseId == 0 || region.ProtectedSharedLifetimeId != 0 ||
			region.ProtectedSharedPageIndex != 0 || region.ProtectedSharedPageCount != 0 ||
			(region.ProtectedSharedOperation == hcsschema.ProtectedSharedInstall && region.HiddenFromGuest) {
			return fmt.Errorf("invalid protected installation/removal request")
		}
	case hcsschema.ProtectedSharedInitialize, hcsschema.ProtectedSharedSeal,
		hcsschema.ProtectedSharedBeginTeardown, hcsschema.ProtectedSharedReclaim:
		if region.ProtectedSharedLeaseId == 0 || region.ProtectedSharedPageCount == 0 ||
			region.ProtectedSharedPageCount > 4 || region.ProtectedSharedPageIndex >= pages ||
			uint64(region.ProtectedSharedPageCount) > pages-region.ProtectedSharedPageIndex ||
			(region.ProtectedSharedOperation == hcsschema.ProtectedSharedInitialize && region.ProtectedSharedLifetimeId != 0) {
			return fmt.Errorf("invalid protected control range/identity")
		}
	default:
		return fmt.Errorf("unsupported protected shared-memory action")
	}
	return nil
}

// ModifyProtectedSharedWithOutcome validates and submits one private action,
// borrowing resource through HCS completion without transferring ownership.
// Callers serialize this entire action/read pair against all other actions and
// receipt reads. Length is bytes; private ranges/counts use 4-KiB pages.
// Preflight failure leaves Dispatched false and performs no receipt query.
// After cancellation the independent cached read has a five-second budget;
// ReceiptError never incorporates the action's failed HRESULT/native status.
// A valid receipt is diagnostic evidence, not proof of zero work or safe release.
func (uvm *UtilityVM) ModifyProtectedSharedWithOutcome(ctx context.Context, region hcsschema.SharedMemoryRegion, resource hcsv2.OperationResource) ProtectedSharedModifyOutcome {
	var outcome ProtectedSharedModifyOutcome
	if err := validateProtectedSharedModify(region, resource); err != nil {
		outcome.ActionError = err
		return outcome
	}
	if uvm.hcsSystem == nil {
		outcome.ActionError = fmt.Errorf("protected operation has no compute system")
		return outcome
	}
	outcome.Dispatched = true
	outcome.ActionError = uvm.hcsSystem.ModifyWithResources(ctx, &hcsschema.ModifySettingRequest{
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
	outcome.Receipt, outcome.ReceiptError = uvm.protectedSharedOperationReceipt(queryCtx, region)
	return outcome
}

// ModifyProtectedShared borrows the controller through the serialized action/
// cached-read pair and returns the receipt even on failure. Length is bytes;
// control ranges are 4-KiB pages. It joins action and independent query/validation
// errors and requires complete action-specific success evidence. Cancellation
// retains the outcome helper's independent five-second query budget; unframed
// work never means zero progress or release authorization.
func (uvm *UtilityVM) ModifyProtectedShared(ctx context.Context, region hcsschema.SharedMemoryRegion, resource hcsv2.OperationResource) (*hcsschema.ProtectedSharedRegionInfo, error) {
	outcome := uvm.ModifyProtectedSharedWithOutcome(ctx, region, resource)
	if !outcome.Dispatched {
		return outcome.Receipt, outcome.ActionError
	}
	p, queryErr := outcome.Receipt, outcome.ReceiptError
	if queryErr == nil {
		queryErr = validateProtectedSharedOperationStatus(p)
	}
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
	return p, errors.Join(outcome.ActionError, queryErr)
}

// ProtectedSharedPartitionOutcome keeps the actual Update failure independent
// of the later cached-property read. Region/Receipt may be present on failure
// for diagnostics, never release authority or live state. Dispatched alone
// proves only submission; even a matching old receipt cannot override an action
// error. The caller serializes the whole action/read pair against all peers.
type ProtectedSharedPartitionOutcome struct {
	Dispatched   bool
	ActionError  error
	Region       *hcsschema.SharedMemoryRegionInfo
	Receipt      *hcsschema.ProtectedSharedPartitionInfo
	ReceiptError error
}

// validateProtectedSharedPartitionRequest checks a whole-partition action on an
// existing owned lease, without dispatch or ownership transfer. Seal requires a
// previously observed actual ID; identity may discover it with expectedID zero.
// Page ranges/lifetime IDs are forbidden, and Length remains a byte count.
func validateProtectedSharedPartitionRequest(region hcsschema.SharedMemoryRegion, expectedID uint64) error {
	if err := ValidateProtectedSharedRegion(region); err != nil {
		return err
	}
	if region.ProtectedSharedLeaseId == 0 || region.ProtectedSharedLifetimeId != 0 ||
		region.ProtectedSharedPageIndex != 0 || region.ProtectedSharedPageCount != 0 {
		return errors.New("partition action requires an owned lease and no page arguments")
	}
	switch region.ProtectedSharedOperation {
	case hcsschema.ProtectedSharedPartitionIdentity:
	case hcsschema.ProtectedSharedSealPartition:
		if expectedID == 0 {
			return errors.New("partition seal requires the previously observed owned target")
		}
	default:
		return errors.New("unsupported protected partition action")
	}
	if expectedID == math.MaxUint64 {
		return errors.New("self partition alias is not an owned target identity")
	}
	return nil
}

// protectedSharedPartitionReceipt selects exactly one named region, validates
// retained owner/lease/page framing and checks the expected partition action and
// target. It ignores the independent last page-action status. Returned pointers
// retain the property snapshot, even when malformed; callers must check error.
// It neither samples native state nor takes ownership of VM/backing resources.
func protectedSharedPartitionReceipt(regions []hcsschema.SharedMemoryRegionInfo, region hcsschema.SharedMemoryRegion, expectedID uint64) (*hcsschema.SharedMemoryRegionInfo, error) {
	var found *hcsschema.SharedMemoryRegionInfo
	for i := range regions {
		if regions[i].SectionName == region.SectionName {
			if found != nil {
				return nil, errors.New("duplicate protected partition region")
			}
			found = &regions[i]
		}
	}
	if found == nil {
		return nil, errors.New("missing protected partition region")
	}
	if _, err := SharedMemoryByteGPA(int64(found.GuestPhysicalAddress), int64(region.Length)); err != nil {
		return found, err
	}
	owner := found.ProtectedShared
	if err := ValidateProtectedSharedOperationResultStructure(owner, region.ProtectedSharedLeaseId, uint64(region.Length)/4096); err != nil {
		return found, err
	}
	if !owner.Prepared || owner.Removed {
		return found, errors.New("partition action region is not a retained prepared owner")
	}
	p := found.ProtectedSharedPartition
	if p == nil || p.Version != 1 || p.Operation != region.ProtectedSharedOperation ||
		!p.PartitionIdValid || p.HypervisorPartitionId == 0 || p.HypervisorPartitionId == math.MaxUint64 ||
		(expectedID != 0 && p.HypervisorPartitionId != expectedID) {
		return found, errors.New("missing, stale or mismatched protected partition receipt")
	}
	return found, nil
}

// ValidateProtectedSharedPartitionOutcome requires successful submission AND a
// validated cached acknowledgment of the expected action/owned target. HRESULT
// must be exactly S_OK, not merely nonnegative. It never interprets false as
// unsealed, and never lets a stale success hide action/query failure. Ownership
// remains with the caller on every path; this function has no side effects.
func ValidateProtectedSharedPartitionOutcome(outcome ProtectedSharedPartitionOutcome, action hcsschema.ProtectedSharedAction, expectedID uint64) error {
	if !outcome.Dispatched {
		return errors.Join(errors.New("partition action was not dispatched"), outcome.ActionError)
	}
	if err := errors.Join(outcome.ActionError, outcome.ReceiptError); err != nil {
		return err
	}
	p := outcome.Receipt
	if p == nil || p.Version != 1 || p.Operation != action ||
		!p.PartitionIdValid || p.HypervisorPartitionId == 0 || p.HypervisorPartitionId == math.MaxUint64 ||
		(expectedID != 0 && p.HypervisorPartitionId != expectedID) || p.OperationHresult != 0 {
		return errors.New("partition action lacks exact successful owned-target receipt")
	}
	switch action {
	case hcsschema.ProtectedSharedPartitionIdentity:
		if p.SealCompleted {
			return errors.New("identity receipt has a seal acknowledgment")
		}
	case hcsschema.ProtectedSharedSealPartition:
		if expectedID == 0 || !p.SealCompleted {
			return errors.New("partition seal lacks synchronous completion")
		}
	default:
		return errors.New("unsupported partition receipt action")
	}
	return nil
}

// ModifyProtectedSharedPartitionWithOutcome submits a normal owned-region Update
// without capabilities or numeric target in the request, then reads its separate
// cached receipt. The caller must exclusively serialize this pair against every
// region action/property observer; HCS stores only the last action, not a nonce.
// expectedID is local validation only (zero permits identity discovery). No
// resources transfer, and failure never authorizes release. Cancellation allows
// the diagnostic read a separate five-second budget. Call the outcome validator
// before using its ID or claiming completion; ReceiptError excludes action status.
func (uvm *UtilityVM) ModifyProtectedSharedPartitionWithOutcome(ctx context.Context, region hcsschema.SharedMemoryRegion, expectedID uint64) ProtectedSharedPartitionOutcome {
	var outcome ProtectedSharedPartitionOutcome
	if err := validateProtectedSharedPartitionRequest(region, expectedID); err != nil {
		outcome.ActionError = err
		return outcome
	}
	if uvm.hcsSystem == nil {
		outcome.ActionError = errors.New("partition action has no compute system")
		return outcome
	}
	outcome.Dispatched = true
	outcome.ActionError = uvm.hcsSystem.Modify(ctx, &hcsschema.ModifySettingRequest{
		ResourcePath: resourcepaths.SharedMemoryRegionResourcePath,
		RequestType:  "Update",
		Settings:     region,
	})
	// A failed/cancelled action still needs independent diagnostics. Its error
	// remains sticky even if HCS returns an older successful cached receipt.
	queryCtx := ctx
	if ctx.Err() != nil {
		var cancel context.CancelFunc
		queryCtx, cancel = context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		defer cancel()
	}
	regions, err := uvm.SharedMemoryRegions(queryCtx)
	if err != nil {
		outcome.ReceiptError = err
		return outcome
	}
	outcome.Region, outcome.ReceiptError = protectedSharedPartitionReceipt(regions, region, expectedID)
	if outcome.Region != nil {
		outcome.Receipt = outcome.Region.ProtectedSharedPartition
	}
	return outcome
}
