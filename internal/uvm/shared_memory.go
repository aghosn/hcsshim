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

// SharedMemoryRegions returns owned copies of configured region properties,
// including cached protected receipts. It does not refresh native lifecycle
// state, prove progress/absence, or authorize release. GPA values are 4-KiB page
// indices. Query/decode failures return no usable regions. Callers serialize
// protected actions and observations; the system protects its handle lifetime.
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

// parseSharedMemoryRegionResponse accepts the ordinary array/legacy wrappers.
// A malformed private frame must not lose its error through a wrapper retry;
// all shapes use the strict v2 decoder, publishing nothing on error.
// Ordinary optional fields and null/empty arrays keep their existing behavior.
func parseSharedMemoryRegionResponse(
	response json.RawMessage,
) ([]hcsschema.SharedMemoryRegionInfo, error) {
	trimmed := bytes.TrimSpace(response)
	if (len(trimmed) != 0 && trimmed[0] == '[') || bytes.Equal(trimmed, []byte("null")) {
		var regions []hcsschema.SharedMemoryRegionInfo
		if err := json.Unmarshal(response, &regions); err != nil {
			return nil, err
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

// SharedMemoryByteGPA converts the native unsigned 4-KiB page index into bytes.
// Length is a positive, page-aligned byte count. Shift/end overflow returns no
// usable address; GPA zero is valid and does not by itself imply installation.
func SharedMemoryByteGPA(page uint64, length int64) (uint64, error) {
	if length <= 0 || length%4096 != 0 || page > math.MaxUint64>>12 {
		return 0, fmt.Errorf("invalid shared-memory page/length: %d/%d", page, length)
	}
	address := page << 12
	if uint64(length) > math.MaxUint64-address {
		return 0, fmt.Errorf("shared-memory byte range overflows")
	}
	return address, nil
}

// ValidateProtectedSharedRegion checks immutable non-hidden protected settings.
// Signed schema byte fields are checked before conversion; both creation roles
// are explicit. This neither validates an action's lease/range nor acquires
// authority: the actual controller capability must accompany native dispatch.
func ValidateProtectedSharedRegion(r hcsschema.SharedMemoryRegion) error {
	if !r.ProtectedShared || r.HiddenFromGuest ||
		r.SectionName == "" || r.ProtectedSharedControllerUri == "" ||
		r.StartOffset < 0 || r.StartOffset%4096 != 0 || r.Length <= 0 || r.Length%4096 != 0 {
		return fmt.Errorf("invalid non-hidden protected shared-memory configuration")
	}
	if r.ProtectedSharedBackingMode != hcsschema.ProtectedSharedBackingBootstrap &&
		r.ProtectedSharedBackingMode != hcsschema.ProtectedSharedBackingImport {
		return fmt.Errorf("protected shared-memory requires explicit Bootstrap or Import mode")
	}
	if uint64(r.Length) > math.MaxUint64-uint64(r.StartOffset) {
		return fmt.Errorf("protected section byte range overflows")
	}
	return nil
}

// validateProtectedSharedOptions checks startup-only fields and exact borrowed
// file-capability matches before creation. Bootstrap expects lease zero; Import
// requires the observed nonzero lease. Ordinary settings remain resource-free
// and cannot smuggle private fields. Unsupported appliance/sibling-root protected
// combinations fail without altering those ordinary boot/storage paths.
// It neither closes originals nor proves that the underlying handles are valid.
func validateProtectedSharedOptions(opts *OptionsLCOW) error {
	controllers := make(map[string]bool)
	sections := make(map[string]bool)
	for _, r := range opts.SharedMemoryRegions {
		if !r.ProtectedShared {
			if r.ProtectedSharedControllerUri != "" ||
				(r.ProtectedSharedBackingMode != "" && r.ProtectedSharedBackingMode != hcsschema.ProtectedSharedBackingNone) ||
				(r.ProtectedSharedOperation != "" && r.ProtectedSharedOperation != hcsschema.ProtectedSharedNone) ||
				r.ProtectedSharedLeaseId != 0 || r.ProtectedSharedLifetimeId != 0 ||
				r.ProtectedSharedPageIndex != 0 || r.ProtectedSharedPageCount != 0 {
				return fmt.Errorf("private shared-memory fields without protected opt-in")
			}
			continue
		}
		if err := ValidateProtectedSharedRegion(r); err != nil {
			return err
		}
		if opts.Appliance != nil || opts.SiblingRoot {
			return fmt.Errorf("protected shared-memory does not support appliance or sibling-root boot")
		}
		if (r.ProtectedSharedOperation != "" && r.ProtectedSharedOperation != hcsschema.ProtectedSharedNone) ||
			r.ProtectedSharedLifetimeId != 0 || r.ProtectedSharedPageIndex != 0 || r.ProtectedSharedPageCount != 0 ||
			(r.ProtectedSharedBackingMode == hcsschema.ProtectedSharedBackingBootstrap && r.ProtectedSharedLeaseId != 0) ||
			(r.ProtectedSharedBackingMode == hcsschema.ProtectedSharedBackingImport && r.ProtectedSharedLeaseId == 0) {
			return fmt.Errorf("invalid protected startup action or expected lease")
		}
		if sections[r.SectionName] {
			return fmt.Errorf("duplicate protected shared-memory section %q", r.SectionName)
		}
		sections[r.SectionName] = true
		controllers[r.ProtectedSharedControllerUri] = true
	}

	// A URI is only a selector. Exactly one real file resource must back each
	// selected controller, and private options must not attach unrelated handles.
	seen := make(map[string]bool)
	for _, resource := range opts.ProtectedSharedResources {
		if !controllers[resource.URI] || seen[resource.URI] ||
			resource.Type != computecore.HcsResourceTypeFile ||
			resource.Handle == 0 || resource.Handle == syscall.InvalidHandle {
			return fmt.Errorf("invalid, duplicate or unselected protected controller capability")
		}
		seen[resource.URI] = true
	}
	for uri := range controllers {
		if !seen[uri] {
			return fmt.Errorf("protected startup requires controller capability %q", uri)
		}
	}
	return nil
}

// ValidateProtectedSharedOperationResultStructure checks complete v2 cached
// framing, local owner consistency and immutable lease/page identity. pages uses
// 4-KiB units; lease zero permits discovery. It does not judge action success.
// InitializedPages is a retained known prefix, never live inventory or reclaim
// proof. The caller exclusively owns p; failure does not invalidate owned native
// resources or authorize discarding progress/owners.
func ValidateProtectedSharedOperationResultStructure(p *hcsschema.ProtectedSharedRegionInfo, lease, pages uint64) error {
	if p == nil || p.Version != 2 || p.LeaseId == 0 || pages == 0 ||
		(lease != 0 && p.LeaseId != lease) || p.PageCount != pages ||
		p.InitializedPages > pages || p.PagesProcessed > 4 || uint64(p.PagesProcessed) > pages ||
		(!p.OperationResultValid && (p.PagesProcessed != 0 || p.OperationStatus != 0)) ||
		(p.Removed && (p.Prepared || p.Installed)) ||
		(p.Installed && (!p.Prepared || p.InitializedPages != pages)) {
		return fmt.Errorf("malformed or mismatched protected operation receipt")
	}
	return nil
}

// validateProtectedSharedOperationStatus reads an already structurally checked
// cached receipt. Failed HRESULT/native NTSTATUS returns diagnostics without
// modifying the receipt. No native query, ownership change or progress inference
// occurs; native status is meaningful only when OperationResultValid is true.
func validateProtectedSharedOperationStatus(p *hcsschema.ProtectedSharedRegionInfo) error {
	if p.OperationHresult&0x80000000 != 0 ||
		(p.OperationResultValid && p.OperationStatus&0x80000000 != 0) {
		return fmt.Errorf("protected action failed: HRESULT=%#08x native-valid=%t status=%#08x processed=%d",
			p.OperationHresult, p.OperationResultValid, p.OperationStatus, p.PagesProcessed)
	}
	return nil
}

// ValidateProtectedSharedOperationResult validates cached structure and status,
// retaining the caller-owned receipt on error. pages uses 4-KiB units; lease
// zero permits discovery. False native validity is legitimate for Install/Remove
// but does not mean zero work. This is not live state or release authorization.
func ValidateProtectedSharedOperationResult(p *hcsschema.ProtectedSharedRegionInfo, lease, pages uint64) error {
	if err := ValidateProtectedSharedOperationResultStructure(p, lease, pages); err != nil {
		return err
	}
	return validateProtectedSharedOperationStatus(p)
}

// ValidateProtectedSharedStartupResult checks the cached result immediately
// after successful native Start, before other actions replace it. Startup owns
// Bootstrap prepare/init/root-revoke/Install or Import/Install, not a GCS helper.
// Install success has no native lifecycle frame: false validity and zero
// status/prefix are required alongside local installed/full-init evidence.
// pages is 4-KiB pages; lease zero discovers the Bootstrap lease. This diagnostic
// snapshot is not a live mapping inventory; callers serialize actions/reads.
func ValidateProtectedSharedStartupResult(p *hcsschema.ProtectedSharedRegionInfo, lease, pages uint64) error {
	if err := ValidateProtectedSharedOperationResult(p, lease, pages); err != nil {
		return err
	}
	if !p.Prepared || !p.Installed || p.Removed || p.InitializedPages != pages || p.OperationResultValid {
		return fmt.Errorf("missing completed protected startup installation receipt")
	}
	return nil
}

// protectedSharedOperationReceipt obtains the section's cached receipt and checks
// geometry, byte-GPA conversion and optional actual lease. It returns diagnostics
// even on structural failure, but those are not validated progress. The caller
// serializes reads/actions; missing or duplicate regions never imply absence of
// native work. No lifecycle operation or live reconciliation is performed.
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
	p := found.ProtectedShared
	if _, err := SharedMemoryByteGPA(found.GuestPhysicalAddress, int64(region.Length)); err != nil {
		return p, err
	}
	return p, ValidateProtectedSharedOperationResultStructure(p, region.ProtectedSharedLeaseId, uint64(region.Length)/4096)
}

// ProtectedSharedOperationResult returns a structurally/status-checked cached
// receipt, including diagnostics on error. Region Length is bytes; its nonzero
// lease must match. Callers serialize observations and actions. Neither a query
// failure nor a cached zero prefix proves no work, absence or safe release.
func (uvm *UtilityVM) ProtectedSharedOperationResult(ctx context.Context, region hcsschema.SharedMemoryRegion) (*hcsschema.ProtectedSharedRegionInfo, error) {
	p, err := uvm.protectedSharedOperationReceipt(ctx, region)
	if err == nil {
		err = validateProtectedSharedOperationStatus(p)
	}
	return p, err
}

// ProtectedSharedModifyOutcome separates native submission attempts, action
// errors and independent cached-receipt observation errors. Dispatched is not
// proof of native execution. ReceiptError covers acquisition/structure only,
// not the action's cached HRESULT. A nonnil Receipt on any failure is diagnostic,
// not correlated live progress: an HCS failure before reaching the worker can
// leave an older cache. Never reconcile absence/reclaim or retry from that cache.
type ProtectedSharedModifyOutcome struct {
	Dispatched   bool
	ActionError  error
	Receipt      *hcsschema.ProtectedSharedRegionInfo
	ReceiptError error
}

// validateProtectedSharedModify checks immutable region settings, actual nonzero
// lease, page bounds and borrowed controller selector/type/handle before dispatch.
// Native checks authoritative identity/rights and immutable equality. Only
// admission/cleanup are allowed; Initialize/Install and preparation are retired
// Modify actions. It neither owns resources nor performs native work.
func validateProtectedSharedModify(region hcsschema.SharedMemoryRegion, resource hcsv2.OperationResource) error {
	if err := ValidateProtectedSharedRegion(region); err != nil {
		return err
	}
	if resource.URI != region.ProtectedSharedControllerUri ||
		resource.Type != computecore.HcsResourceTypeFile ||
		resource.Handle == 0 || resource.Handle == syscall.InvalidHandle ||
		region.ProtectedSharedLeaseId == 0 {
		return fmt.Errorf("protected operation controller or actual lease mismatch")
	}
	pages := uint64(region.Length) / 4096
	switch region.ProtectedSharedOperation {
	case hcsschema.ProtectedSharedRemove:
		if region.ProtectedSharedLifetimeId != 0 || region.ProtectedSharedPageIndex != 0 || region.ProtectedSharedPageCount != 0 {
			return fmt.Errorf("invalid protected removal range")
		}
	case hcsschema.ProtectedSharedSeal, hcsschema.ProtectedSharedBeginTeardown, hcsschema.ProtectedSharedReclaim:
		if region.ProtectedSharedPageCount == 0 || region.ProtectedSharedPageCount > 4 ||
			region.ProtectedSharedPageIndex >= pages ||
			uint64(region.ProtectedSharedPageCount) > pages-region.ProtectedSharedPageIndex {
			return fmt.Errorf("invalid protected control page range")
		}
	default:
		return fmt.Errorf("unsupported protected Modify action %q", region.ProtectedSharedOperation)
	}
	return nil
}

// ModifyProtectedSharedWithOutcome validates and submits one admission/cleanup
// action, borrowing the original controller through native completion. The
// caller serializes the whole action/read pair and retains immutable settings.
// Length/offset are bytes; private ranges use 4-KiB pages. Preflight failure
// does not query an older cache. After dispatch, receipt acquisition always has
// a bounded five-second budget, detached only if the action context expired.
// Cancellation/failed receipt acquisition never proves no work or safe release.
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
	outcome.Dispatched, outcome.ActionError = uvm.hcsSystem.ModifyWithResourcesOutcome(ctx, &hcsschema.ModifySettingRequest{
		ResourcePath: resourcepaths.SharedMemoryRegionResourcePath,
		RequestType:  "Update",
		Settings:     region,
	}, []hcsv2.OperationResource{resource})
	if !outcome.Dispatched {
		return outcome
	}

	// Preserve post-cancellation diagnostics without an unbounded query, and
	// without treating a cache as proof that the submitted action ran.
	queryParent := ctx
	if ctx.Err() != nil {
		queryParent = context.WithoutCancel(ctx)
	}
	queryCtx, cancel := context.WithTimeout(queryParent, 5*time.Second)
	defer cancel()
	outcome.Receipt, outcome.ReceiptError = uvm.protectedSharedOperationReceipt(queryCtx, region)
	if outcome.ReceiptError == nil {
		// A structurally intact cache can still contradict the submitted
		// action's framing/bounds. Preserve it as diagnostics, not progress.
		p := outcome.Receipt
		if region.ProtectedSharedOperation == hcsschema.ProtectedSharedRemove {
			if p.OperationResultValid {
				outcome.ReceiptError = errors.New("unexpected native lifecycle frame for removal")
			}
		} else if p.OperationResultValid && p.PagesProcessed > region.ProtectedSharedPageCount {
			outcome.ReceiptError = errors.New("native prefix exceeds requested page count")
		}
	}
	return outcome
}

// ModifyProtectedShared returns cached diagnostics even on failure, joining
// action and independent receipt/status errors. A successful call requires the
// action's complete native prefix, or Remove's local owner flags and no native
// frame. InitializedPages is retained history, never reclaim proof. Borrowed
// controller ownership and whole action/read serialization remain with callers;
// no retries or cached-progress reconciliation occur on uncertainty.
func (uvm *UtilityVM) ModifyProtectedShared(ctx context.Context, region hcsschema.SharedMemoryRegion, resource hcsv2.OperationResource) (*hcsschema.ProtectedSharedRegionInfo, error) {
	outcome := uvm.ModifyProtectedSharedWithOutcome(ctx, region, resource)
	if !outcome.Dispatched {
		return outcome.Receipt, outcome.ActionError
	}
	p, receiptErr := outcome.Receipt, outcome.ReceiptError
	if receiptErr == nil {
		receiptErr = validateProtectedSharedOperationStatus(p)
	}
	if receiptErr == nil {
		if region.ProtectedSharedOperation == hcsschema.ProtectedSharedRemove {
			if p.OperationResultValid || !p.Removed {
				receiptErr = errors.New("missing actual removal ownership receipt")
			}
		} else if !p.OperationResultValid || p.PagesProcessed != region.ProtectedSharedPageCount {
			receiptErr = errors.New("missing complete native operation receipt")
		}
	}
	return p, errors.Join(outcome.ActionError, receiptErr)
}
