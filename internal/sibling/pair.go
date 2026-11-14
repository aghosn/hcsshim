//go:build windows

package sibling

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/Microsoft/go-winio/pkg/guid"
	"github.com/Microsoft/hcsshim/internal/diodecontrol"
	hcsschema "github.com/Microsoft/hcsshim/internal/hcs/schema2"
	"github.com/Microsoft/hcsshim/internal/protocol/guestresource"
	"github.com/Microsoft/hcsshim/internal/uvm"
	"github.com/Microsoft/hcsshim/internal/uvm/scsi"
	"github.com/Microsoft/hcsshim/internal/vm/vmutils"
	"golang.org/x/sync/errgroup"
)

// Config is an explicit host-side opt-in; it never names existing HCS systems.
// The workload inherits the sandbox's security/integrity options without alteration.
// Protected masks are optional decimal strings: nil is omitted, not selected zero.
// RunID and CleanupReceiptPath identify the one final S3 cleanup result; early/late
// AHV selection is already encoded in prepared boot inputs, not another shim flag.
// The protected profile requires interactive endpoint acquisition before sealing.
// PageMetadataOutputPath optionally exports an existing local directory writable
// only to the protected diode; preflight validates the filesystem destination.
type Config struct {
	Version                   int     `json:"version"`
	ModuleDirectory           string  `json:"module_directory"`
	SharedMemoryBytes         uint64  `json:"shared_memory_bytes"`
	WorkloadGuestStateFile    string  `json:"workload_guest_state_file"`
	Interactive               bool    `json:"interactive,omitempty"`
	MediateGCS                bool    `json:"mediate_gcs,omitempty"`
	UnikraftPackage           string  `json:"unikraft_package,omitempty"`
	ProtectedShared           bool    `json:"protected_shared,omitempty"`
	DiodePartitionSealMask    *uint64 `json:"diode_partition_seal_mask,omitempty,string"`
	WorkloadPartitionSealMask *uint64 `json:"workload_partition_seal_mask,omitempty,string"`
	RunID                     string  `json:"run_id,omitempty"`
	CleanupReceiptPath        string  `json:"cleanup_receipt_path,omitempty"`
	PageMetadataOutputPath    string  `json:"page_metadata_output_path,omitempty"`
}

func LoadConfig(path string) (*Config, error) {
	if !filepath.IsAbs(path) {
		return nil, errors.New("sibling pair config path must be absolute")
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	return decodeConfig(file)
}

func decodeConfig(reader io.Reader) (*Config, error) {
	limited := &io.LimitedReader{R: reader, N: (64 << 10) + 1}
	decoder := json.NewDecoder(limited)
	var raw json.RawMessage
	if err := decoder.Decode(&raw); err != nil {
		return nil, err
	}
	var extra interface{}
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return nil, errors.New("sibling pair config contains trailing data")
	}
	if limited.N == 0 {
		return nil, errors.New("sibling pair config exceeds 64 KiB")
	}
	if err := validateConfigMasks(raw); err != nil {
		return nil, err
	}
	decoder = json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var config Config
	if err := decoder.Decode(&config); err != nil {
		return nil, err
	}
	if config.Version != 1 || !filepath.IsAbs(config.ModuleDirectory) ||
		config.SharedMemoryBytes < 1<<20 || config.SharedMemoryBytes > 0x7ffff000 ||
		config.SharedMemoryBytes%4096 != 0 {
		return nil, errors.New("sibling pair requires version 1, an absolute module directory and page-aligned shared memory in 1 MiB..2 GiB")
	}
	if config.WorkloadGuestStateFile == "" || filepath.Base(config.WorkloadGuestStateFile) != config.WorkloadGuestStateFile ||
		strings.ContainsAny(config.WorkloadGuestStateFile, "\\/:\x00") || !strings.EqualFold(filepath.Ext(config.WorkloadGuestStateFile), ".vmgs") {
		return nil, errors.New("sibling workload guest state must be a VMGS filename under the existing boot files directory")
	}
	if config.UnikraftPackage != "" && (!filepath.IsAbs(config.UnikraftPackage) ||
		config.SharedMemoryBytes != 32<<20) {
		return nil, errors.New("owned Unikraft requires an absolute package path and a 32 MiB section")
	}
	if config.ProtectedShared {
		if !config.MediateGCS || !config.Interactive || config.SharedMemoryBytes != 32<<20 || config.UnikraftPackage != "" ||
			config.RunID == "" || len(config.RunID) > 128 ||
			strings.Trim(config.RunID, "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_") != "" ||
			!filepath.IsAbs(config.CleanupReceiptPath) || strings.ContainsRune(config.CleanupReceiptPath, '\x00') {
			return nil, errors.New("protected owned pair requires mediated GCS/root, interactive endpoints, 32 MiB, Linux, a simple run ID and an absolute cleanup receipt path")
		}
	} else if config.DiodePartitionSealMask != nil || config.WorkloadPartitionSealMask != nil ||
		config.RunID != "" || config.CleanupReceiptPath != "" {
		return nil, errors.New("partition masks and cleanup receipt identity require protected_shared")
	}
	if config.PageMetadataOutputPath != "" {
		volume := filepath.VolumeName(config.PageMetadataOutputPath)
		if !config.ProtectedShared || !filepath.IsAbs(config.PageMetadataOutputPath) ||
			len(volume) != 2 || volume[1] != ':' ||
			!strings.ContainsAny(volume[:1], "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ") ||
			strings.ContainsAny(config.PageMetadataOutputPath[2:], ":\x00") {
			return nil, errors.New("page metadata output requires the protected owned Linux profile and an absolute local drive directory path")
		}
	}
	return &config, nil
}

// validateConfigMasks rejects ambiguous selection before normal strict decoding.
// Only unsigned decimal JSON strings are accepted; omission is not selected zero.
func validateConfigMasks(raw []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	token, err := decoder.Token()
	if err != nil || token != json.Delim('{') {
		return errors.New("sibling pair config must be an object")
	}
	seen := make(map[string]bool)
	for decoder.More() {
		token, err := decoder.Token()
		if err != nil {
			return err
		}
		name := token.(string)
		var value json.RawMessage
		if err := decoder.Decode(&value); err != nil {
			return err
		}
		switch {
		case strings.EqualFold(name, "diode_partition_seal_mask"):
			name = "diode_partition_seal_mask"
		case strings.EqualFold(name, "workload_partition_seal_mask"):
			name = "workload_partition_seal_mask"
		default:
			continue
		}
		if seen[name] {
			return fmt.Errorf("duplicate partition mask %q", name)
		}
		seen[name] = true
		var text string
		if err := json.Unmarshal(value, &text); err != nil || text == "" ||
			strings.Trim(text, "0123456789") != "" {
			return fmt.Errorf("%s must be an unsigned decimal string, not null or a JSON number", name)
		}
		if _, err := strconv.ParseUint(text, 10, 64); err != nil {
			return fmt.Errorf("%s: %w", name, err)
		}
	}
	return nil
}

// Pair is the sole lifetime owner of two newly created UVMs and their shared
// section. The sandbox owns Pair closure; protected participant/service loss
// also requests native shutdown independently of workload task cleanup.
type Pair struct {
	Workload        *uvm.UtilityVM
	Diode           *uvm.UtilityVM
	section         *Section
	uplinkCleanup   func() error
	closeOnce       sync.Once
	closeErr        error
	done            chan struct{}
	unikraft        bool
	unikraftConsole *ownedUnikraftConsole
	protected       *protectedPair
	// Closers are captured immediately after acquisition so partial startup
	// follows the same consumer-before-provider ownership order.
	workloadCloser    io.Closer
	diodeCloser       io.Closer
	sectionCloser     io.Closer
	interactiveCloser io.Closer
}

// commonPairOptions clones security and role settings without acquiring backing.
// Callers assign either an ordinary section or a real protected capability later.
func commonPairOptions(base *uvm.OptionsLCOW, config *Config, group string) (*uvm.OptionsLCOW, *uvm.OptionsLCOW, error) {
	if base == nil || base.Options == nil || base.ConfidentialLCOWOptions == nil ||
		base.ConfidentialCommonOptions == nil || !base.UseGuestConnection ||
		!base.SecurityPolicyEnabled || !base.DmVerityMode || base.GuestStateFilePath == "" ||
		base.SCSIControllerCount == 0 || !filepath.IsAbs(base.BundleDirectory) || base.ID == "" ||
		base.SiblingRoot || strings.EqualFold(base.GuestStateFilePath, config.WorkloadGuestStateFile) {
		return nil, nil, errors.New("sibling pair requires GCS, SNP dm-verity boot, a bundle directory and SCSI")
	}
	if len(base.SharedMemoryRegions) != 0 || len(base.SiblingCommunicationEndpoints) != 0 || len(base.AssignedDevices) != 0 {
		return nil, nil, errors.New("sibling pair cannot inherit shared regions, endpoint ownership or assigned devices")
	}
	// Each guest owns independent mutable option structs; policy bytes are unchanged.
	clone := func(role Role, id, bundle string) (*uvm.OptionsLCOW, error) {
		options := *base
		common := *base.Options
		confidential := *base.ConfidentialLCOWOptions
		security := *base.ConfidentialCommonOptions
		options.Options, options.ConfidentialLCOWOptions = &common, &confidential
		options.ConfidentialCommonOptions = &security
		options.ID, options.BundleDirectory = id, bundle
		options.KernelBootOptions = strings.TrimSpace(base.KernelBootOptions + " hcs_shmem_diag.role=" + string(role))
		endpoint, err := Endpoint(role, group)
		if err != nil {
			return nil, err
		}
		options.SiblingCommunicationEndpoints = []hcsschema.SiblingCommunicationEndpoint{endpoint}
		if role == Workload {
			options.SiblingRoot = true
			options.GuestStateFilePath = config.WorkloadGuestStateFile
			options.VPMemDeviceCount = 0
		} else {
			options.SiblingRoot = false
		}
		return &options, nil
	}
	workload, err := clone(Workload, base.ID, base.BundleDirectory)
	if err != nil {
		return nil, nil, err
	}
	diode, err := clone(Diode, base.ID+"-diode", filepath.Join(base.BundleDirectory, "diode"))
	return workload, diode, err
}

// pairOptions adds ordinary mapped-section settings to the common role options.
func pairOptions(base *uvm.OptionsLCOW, config *Config, group string, section *Section) (*uvm.OptionsLCOW, *uvm.OptionsLCOW, error) {
	workload, diode, err := commonPairOptions(base, config, group)
	if err != nil {
		return nil, nil, err
	}
	for _, options := range []*uvm.OptionsLCOW{workload, diode} {
		options.SharedMemoryRegions = []uvm.LCOWSharedMemoryRegion{{
			SectionName: section.HCSName, Length: int32(section.Size), AllowGuestWrite: true,
		}}
		options.SiblingCommunicationEndpoints[0].SharedMemorySectionName = section.HCSName
	}
	return workload, diode, nil
}

// Start creates and bootstraps a pair in-process. Workload boot and diode root
// provider bootstrap must overlap: the workload cannot reach GCS without root0.
// Protected errors run the single cleanup decision; incomplete owners stay
// retained in-process even when no sandbox task was published.
func Start(ctx context.Context, base *uvm.OptionsLCOW, config *Config) (_ *Pair, resultErr error) {
	ctx, cancelStartup := context.WithCancel(ctx)
	defer cancelStartup()
	if config == nil {
		return nil, errors.New("sibling pair config is nil")
	}
	// Validate programmatic callers as strictly as annotation/config-file callers.
	encoded, err := json.Marshal(config)
	if err != nil {
		return nil, err
	}
	config, err = decodeConfig(strings.NewReader(string(encoded)))
	if err != nil {
		return nil, err
	}
	if config.ProtectedShared {
		pair, err := startProtectedPair(ctx, base, config)
		if err != nil && pair != nil {
			err = errors.Join(err, pair.Close())
		}
		return pair, err
	}
	native, err := loadOwnedUnikraft(config)
	if err != nil {
		return nil, err
	}
	for _, module := range config.moduleInputs() {
		info, err := os.Stat(filepath.Join(config.ModuleDirectory, module))
		if err != nil {
			return nil, fmt.Errorf("sibling pair input %s is unavailable: %w", module, err)
		}
		if !info.Mode().IsRegular() {
			return nil, fmt.Errorf("sibling pair input %s is not a regular file", module)
		}
	}
	group, err := guid.NewV4()
	if err != nil {
		return nil, err
	}
	pair := &Pair{done: make(chan struct{}), unikraft: native != nil}
	var nativeControl *diodecontrol.Client
	defer func() {
		if resultErr != nil {
			if nativeControl != nil {
				resultErr = errors.Join(resultErr, nativeControl.Err())
			}
			if pair.unikraftConsole != nil {
				resultErr = errors.Join(resultErr, pair.unikraftConsole.Err())
			}
			resultErr = errors.Join(resultErr, pair.Close())
		}
	}()
	pair.section, err = CreateSection("hcsshim-sibling-"+group.String(), config.SharedMemoryBytes)
	if err != nil {
		return nil, err
	}
	pair.sectionCloser = pair.section
	workloadOptions, diodeOptions, err := pairOptions(base, config, group.String(), pair.section)
	if err != nil {
		return nil, err
	}
	if native != nil {
		if err := configureOwnedUnikraft(workloadOptions, diodeOptions, config, native, group.String()); err != nil {
			return nil, err
		}
	}
	if err := os.Mkdir(diodeOptions.BundleDirectory, 0700); err != nil {
		return nil, fmt.Errorf("create owned diode bundle: %w", err)
	}
	pair.Workload, err = uvm.CreateLCOW(ctx, workloadOptions)
	if pair.Workload != nil {
		pair.workloadCloser = pair.Workload
	}
	if err != nil {
		return nil, fmt.Errorf("create sibling workload: %w", err)
	}
	if native != nil {
		if err := pair.prepareOwnedUnikraft(diodeOptions, native); err != nil {
			return nil, err
		}
		cancelOnProviderLoss(ctx, pair.unikraftConsole, cancelStartup)
	}
	pair.Diode, err = uvm.CreateLCOW(ctx, diodeOptions)
	if pair.Diode != nil {
		pair.diodeCloser = pair.Diode
	}
	if err != nil {
		return nil, fmt.Errorf("create sibling diode: %w", err)
	}
	if config.MediateGCS {
		if err := pair.Workload.ConfigureGCSRelay(pair.Diode); err != nil {
			return nil, fmt.Errorf("configure sibling GCS relay before boot: %w", err)
		}
	}
	dns, err := HostDNSServers()
	if err != nil {
		return nil, err
	}
	err = bootstrap(ctx, func(bootCtx context.Context) error {
		if err := pair.Workload.Start(bootCtx); err != nil {
			return fmt.Errorf("start sibling workload: %w", err)
		}
		return nil
	}, func(bootCtx context.Context) error {
		if err := pair.Diode.Start(bootCtx); err != nil {
			return fmt.Errorf("start sibling diode: %w", err)
		}
		if native != nil {
			var err error
			nativeControl, err = pair.Diode.NativeStorageControl()
			if err != nil {
				return err
			}
			cancelOnProviderLoss(ctx, nativeControl, cancelStartup)
			return pair.unikraftConsole.waitReady(bootCtx)
		}
		root, err := pair.Diode.SCSIManager.AddVirtualDisk(bootCtx,
			filepath.Join(workloadOptions.BundleDirectory, vmutils.DefaultDmVerityRootfsVhd), true, pair.Diode.ID(), "", nil)
		if err != nil {
			return fmt.Errorf("attach workload root to diode: %w", err)
		}
		// Root0 remains attached until both guests are stopped; never release it
		// under a live provider, even on a failed or canceled bootstrap.
		for _, name := range []string{"sibling_bus.ko", "diode_storvsp.ko", "diode_netvsp.ko", "diode_iptables", "demo.sh", "diode-controller"} {
			if err := pair.Diode.Share(bootCtx, filepath.Join(config.ModuleDirectory, name), "/run/sibling/"+name, true); err != nil {
				return err
			}
		}
		resolve, err := RPDeviceCommand(root.Controller(), root.LUN())
		if err != nil {
			return err
		}
		if _, err := runGuest(bootCtx, pair.Diode, BusLoadCommand("/run/sibling/sibling_bus.ko/sibling_bus.ko")+
			resolve+`insmod /run/sibling/diode_storvsp.ko/diode_storvsp.ko "backends=$storage_dev" luns=0 read_only=true`); err != nil {
			return fmt.Errorf("bootstrap permanent sibling root provider: %w", err)
		}
		uplink, cleanup, err := AttachUplink(bootCtx, pair.Diode)
		if err != nil {
			return err
		}
		pair.uplinkCleanup = cleanup
		_, err = runGuest(bootCtx, pair.Diode, diodeBootstrapCommand(uplink, config.MediateGCS))
		return err
	})
	if err != nil {
		return nil, err
	}
	// Validate native route registration instead of guessing event IDs/GPAs.
	for _, item := range []struct {
		vm      *uvm.UtilityVM
		options *uvm.OptionsLCOW
	}{
		{pair.Diode, diodeOptions}, {pair.Workload, workloadOptions},
	} {
		if _, err := WaitForRoute(ctx, item.vm, item.options.SiblingCommunicationEndpoints[0]); err != nil {
			return nil, err
		}
	}
	for _, name := range []string{"sibling_bus.ko", "demo.sh", "diode-controller"} {
		if err := pair.Workload.Share(ctx, filepath.Join(config.ModuleDirectory, name), "/run/sibling/"+name, true); err != nil {
			return nil, err
		}
	}
	nicCtx, nicCancel := context.WithTimeout(ctx, 30*time.Second)
	defer nicCancel()
	nicCommand := workloadNICCommand()
	ip, gateway := "10.200.0.2", "10.200.0.1"
	if native != nil {
		nicCommand = workloadNICCommandForMAC(native.Network.PeerMAC.String())
		ip, gateway = native.Network.Peer.String(), native.Network.Provider.String()
	}
	device, err := runGuest(nicCtx, pair.Workload, demoToolsStage+nicCommand)
	if err != nil {
		return nil, err
	}
	device = strings.TrimSpace(device)
	if !guestresource.IsSiblingVMBusDeviceID(device) {
		return nil, fmt.Errorf("invalid workload peer NIC identity %q", device)
	}
	if err := pair.Workload.ConfigureSiblingNetworking(guestresource.LCOWNetworkAdapter{
		ID: device, DNSServerList: strings.Join(dns, ","),
		IPConfigs: []guestresource.LCOWIPConfig{{IPAddress: ip, PrefixLength: 30}},
		Routes:    []guestresource.LCOWRoute{{DestinationPrefix: "0.0.0.0/0", NextHop: gateway}},
	}); err != nil {
		return nil, err
	}
	var control scsi.SiblingExportControl
	if native != nil {
		control = nativeControl
	} else {
		linuxControl, err := NewExportControl(pair.Diode)
		if err != nil {
			return nil, err
		}
		controlCtx, controlCancel := context.WithTimeout(ctx, 30*time.Second)
		defer controlCancel()
		if err := linuxControl.checkProvider(controlCtx); err != nil {
			return nil, err
		}
		control = linuxControl
	}
	backend, err := scsi.NewSiblingHostBackend(pair.Diode.SCSIManager, pair.Diode.ID(), control)
	if err != nil {
		return nil, err
	}
	if err := pair.Workload.ConfigureSiblingStorage(backend); err != nil {
		return nil, err
	}
	if config.Interactive {
		pair.interactiveCloser, err = startPairShells(pair)
		if err != nil {
			return nil, fmt.Errorf("start sibling interactive shells: %w", err)
		}
	}
	if native != nil {
		if err := nativeControl.Err(); err != nil {
			return nil, err
		}
		if err := pair.unikraftConsole.Err(); err != nil {
			return nil, err
		}
		pair.watchOwnedProvider(nativeControl)
	} else {
		go func() {
			_ = pair.Diode.Wait()
			_ = pair.Close()
		}()
	}
	return pair, nil
}

func bootstrap(ctx context.Context, workload, diode func(context.Context) error) error {
	ctx, cancel := context.WithTimeout(ctx, 3*time.Minute)
	defer cancel()
	group, ctx := errgroup.WithContext(ctx)
	group.Go(func() error { return workload(ctx) })
	group.Go(func() error { return diode(ctx) })
	return group.Wait()
}

const demoToolsStage = `mkdir -p /run/sibling-exec && mount -t tmpfs -o exec,size=16m tmpfs /run/sibling-exec || exit 1; ` +
	`for tool in demo.sh diode-controller; do ` +
	`cp /run/sibling/$tool/$tool /run/sibling-exec/$tool && chmod 755 /run/sibling-exec/$tool || exit 1; done; `

// GCSRelayCommand starts the same guest relay for standalone and shim-owned pairs.
func GCSRelayCommand() string {
	return `rm -f /run/gcs-relay.ready; ` +
		`/bin/gcs -sibling-relay -relay-ready /run/gcs-relay.ready </dev/null >/run/gcs-relay.log 2>&1 & relay_pid=$!; ` +
		`echo "$relay_pid" >/run/gcs-relay.pid; ` +
		`relay_wait=0; until [ -f /run/gcs-relay.ready ]; do ` +
		`if ! kill -0 "$relay_pid" 2>/dev/null; then cat /run/gcs-relay.log; exit 1; fi; ` +
		`relay_wait=$((relay_wait + 1)); if [ "$relay_wait" -ge 100 ]; then ` +
		`kill "$relay_pid"; cat /run/gcs-relay.log; echo 'GCS relay startup timed out' >&2; exit 1; fi; ` +
		`sleep 0.1; done; echo 'GCS_RELAY_READY: workload control and stdio through diode; Plan9 unchanged'`
}

func diodeBootstrapCommand(uplink *Uplink, mediateGCS bool) string {
	command := diodeNetworkCommand(uplink)
	if mediateGCS {
		command += "; " + GCSRelayCommand()
	}
	return command
}

func diodeNetworkCommand(uplink *Uplink) string {
	return `insmod /run/sibling/diode_netvsp.ko/diode_netvsp.ko; ` +
		`until [ -e /sys/class/net/dvsp0 ]; do sleep 0.1; done; ` +
		`ip addr add 10.200.0.1/30 dev dvsp0; ip link set dvsp0 up; ` +
		`until up=; count=0; for p in /sys/class/net/*; do [ -e "$p/device" ] || continue; ` +
		`d=$(readlink -f "$p/device"); case ${d##*/} in bus*-relid*) continue;; esac; ` +
		`up=${p##*/}; count=$((count+1)); done; [ "$count" -le 1 ] || exit 1; [ "$count" -eq 1 ]; do sleep 0.1; done; ` +
		"ip addr add " + Quote(uplink.Address) + ` dev "$up"; ip link set "$up" up; ` +
		"ip route replace default via " + Quote(uplink.Gateway) + ` dev "$up"; ` +
		demoToolsStage +
		`cp /run/sibling/diode_iptables/diode_iptables /run/sibling-exec/ipt; chmod 755 /run/sibling-exec/ipt; ` +
		`echo 1 >/proc/sys/net/ipv4/ip_forward; ` +
		`/run/sibling-exec/ipt iptables -w -t nat -A POSTROUTING -s 10.200.0.0/30 -o "$up" -j MASQUERADE`
}

func workloadNICCommand() string {
	return workloadNICCommandForMAC("")
}

func workloadNICCommandForMAC(mac string) string {
	return BusLoadCommand("/run/sibling/sibling_bus.ko/sibling_bus.ko") +
		workloadNICDiscoveryCommandForMAC(mac)
}

// workloadNICDiscoveryCommandForMAC selects the peer NIC without provisioning
// modules. Callers must first load or require the registered sibling adapter.
func workloadNICDiscoveryCommandForMAC(mac string) string {
	checkMAC := ""
	if mac != "" {
		checkMAC = `[ "$(cat "$p/address")" = ` + Quote(mac) + ` ] || { echo 'workload peer MAC differs from Unikraft manifest' >&2; exit 1; }; `
	}
	return `set -- /sys/bus/vmbus/drivers/sibling_bus/*-*/sibling_instance; [ "$#" -eq 1 ]; ` +
		`until grep -q 'ready=1' "$1"; do sleep 0.1; done; ` +
		`set -- $(cat "$1"); [ "$#" -eq 5 ]; sb_bus=${1#*=}; [ "${2#*=}" = 3 ]; [ "${3#*=}" = 4 ]; [ "${4#*=}" = 4 ]; [ "${5#*=}" = 1 ]; ` +
		`until count=0; dev=; for p in /sys/class/net/*; do [ -e "$p/device" ] || continue; ` +
		`d=$(readlink -f "$p/device"); case ${d##*/} in bus${sb_bus}-relid*) ` +
		`[ "$(basename "$(readlink "$p/device/driver")")" = hv_netvsc ] || exit 1; ` + checkMAC + `dev=${d##*/}; count=$((count+1));; ` +
		`*) echo 'direct RP NIC detected on workload' >&2; exit 1;; esac; done; [ "$count" -le 1 ] || exit 1; ` +
		`[ "$count" -eq 1 ]; do sleep 0.1; done; printf '%s\n' "$dev"`
}

// Close makes one cleanup decision. Protected native dispatch is serialized with
// termination and reclaim, independently of child-task or guest IO completion.
// Native incompleteness and released-with-publication-failure are cached, never replayed.
func (p *Pair) Close() error {
	return p.close(nil)
}

func (p *Pair) close(cause error) error {
	if p == nil {
		return nil
	}
	if p.protected != nil {
		p.protected.stop(cause)
		// All callers share the one decision, including publication failures.
		p.closeOnce.Do(func() {
			p.closeErr = p.protected.close()
		})
		return p.closeErr
	}
	p.closeOnce.Do(func() {
		p.closeErr = cause
		if p.done != nil {
			close(p.done)
		}
		if p.interactiveCloser != nil {
			p.closeErr = errors.Join(p.closeErr, p.interactiveCloser.Close())
		}
		// The provider and section outlive the consumer, including failed boots.
		if p.workloadCloser != nil {
			p.closeErr = errors.Join(p.closeErr, p.workloadCloser.Close())
		}
		if p.diodeCloser != nil {
			p.closeErr = errors.Join(p.closeErr, p.diodeCloser.Close())
		}
		if p.unikraftConsole != nil {
			p.closeErr = errors.Join(p.closeErr, p.unikraftConsole.Close())
		}
		if p.uplinkCleanup != nil {
			p.closeErr = errors.Join(p.closeErr, p.uplinkCleanup())
		}
		if p.sectionCloser != nil {
			p.closeErr = errors.Join(p.closeErr, p.sectionCloser.Close())
		}
	})
	return p.closeErr
}
