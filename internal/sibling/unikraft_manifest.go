//go:build windows

package sibling

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"strconv"
	"strings"

	"github.com/Microsoft/go-winio/pkg/guid"
	"github.com/Microsoft/hcsshim/internal/protocol/guestrequest"
)

type UnikraftNetwork struct {
	Uplink, Gateway, Provider, Peer netip.Addr
	ProviderMAC, PeerMAC            net.HardwareAddr
}

type UnikraftLUN struct {
	Root, Exported uint8
	ReadOnly       bool
}

type UnikraftConfig struct {
	Idle        string
	MemoryMB    uint64
	Controller  string
	LUNs        []UnikraftLUN
	Network     *UnikraftNetwork
	GCSRelay    bool
	LiveStorage bool
}

// ParseUnikraftManifest reads the authored IGVM input, not runtime overrides.
func ParseUnikraftManifest(reader io.Reader) (*UnikraftConfig, error) {
	var manifest struct {
		Arch   string `json:"guest_arch"`
		Guests []struct {
			Image struct {
				Direct *struct {
					Processors uint64 `json:"processor_count"`
					Pages      uint64 `json:"memory_page_count"`
					Linux      struct {
						CommandLine string `json:"command_line"`
					} `json:"linux"`
				} `json:"snp_linux_direct"`
			} `json:"image"`
		} `json:"guest_configs"`
	}
	limited := &io.LimitedReader{R: reader, N: 65537}
	decoder := json.NewDecoder(limited)
	if err := decoder.Decode(&manifest); err != nil {
		return nil, fmt.Errorf("decode Unikraft launch manifest: %w", err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF || limited.N == 0 {
		return nil, errors.New("unikraft manifest must contain one JSON document of at most 64 KiB")
	}
	if manifest.Arch != "x64" || len(manifest.Guests) != 1 || manifest.Guests[0].Image.Direct == nil {
		return nil, errors.New("unikraft requires one x64 snp_linux_direct image")
	}
	image := manifest.Guests[0].Image.Direct
	if image.Processors != 1 || image.Pages < 16384 || image.Pages > 1048576 || image.Pages%256 != 0 {
		return nil, errors.New("unikraft requires one VP and 64..4096 MiB of whole-MiB guest RAM")
	}
	cfg := &UnikraftConfig{MemoryMB: image.Pages / 256}
	params := map[string]string{}
	application := false
	for _, field := range strings.Fields(image.Linux.CommandLine) {
		if field == "--" {
			application = true
		}
		if !strings.HasPrefix(field, "libukbus_vmbus.") {
			continue
		}
		key, value, ok := strings.Cut(strings.TrimPrefix(field, "libukbus_vmbus."), "=")
		if application || !ok || value == "" || params[key] != "" {
			return nil, fmt.Errorf("invalid, duplicate or post-separator Unikraft parameter %q", field)
		}
		params[key] = value
	}
	take := func(key string) string {
		value := params[key]
		delete(params, key)
		return value
	}
	cfg.Idle = take("idle")
	if cfg.Idle == "" {
		cfg.Idle = "halt"
	}
	if cfg.Idle != "halt" && cfg.Idle != "poll" {
		return nil, errors.New("unikraft idle policy must be halt or poll")
	}
	for _, selection := range []struct {
		name   string
		target *bool
	}{{"gcs_relay", &cfg.GCSRelay}, {"live_storage", &cfg.LiveStorage}} {
		value := take(selection.name)
		if value != "" && value != "0" && value != "1" {
			return nil, fmt.Errorf("unikraft %s must be 0 or 1", selection.name)
		}
		*selection.target = value == "1"
	}
	controller, luns := take("storage_controller"), take("storage_luns")
	if controller != "" || luns != "" {
		id, err := guid.FromString(controller)
		if err != nil || luns == "" {
			return nil, errors.New("unikraft storage requires a controller GUID and explicit LUN mappings")
		}
		cfg.Controller = id.String()
		known := false
		for _, candidate := range guestrequest.ScsiControllerGuids {
			known = known || strings.EqualFold(candidate, cfg.Controller)
		}
		if !known {
			return nil, errors.New("unikraft storage controller must use an existing HCS SCSI controller GUID")
		}
		roots, exports := map[uint8]bool{}, map[uint8]bool{}
		for _, mapping := range strings.Split(luns, ",") {
			fields := strings.Split(mapping, ":")
			if len(fields) != 3 {
				return nil, fmt.Errorf("invalid Unikraft LUN mapping %q", mapping)
			}
			root, e1 := strconv.ParseUint(fields[0], 10, 8)
			exported, e2 := strconv.ParseUint(fields[1], 10, 8)
			if e1 != nil || e2 != nil || root >= 64 || exported == 255 ||
				(fields[2] != "ro" && fields[2] != "rw") || roots[uint8(root)] || exports[uint8(exported)] {
				return nil, fmt.Errorf("invalid or duplicate Unikraft LUN mapping %q", mapping)
			}
			roots[uint8(root)], exports[uint8(exported)] = true, true
			cfg.LUNs = append(cfg.LUNs, UnikraftLUN{uint8(root), uint8(exported), fields[2] == "ro"})
		}
		if len(cfg.LUNs) > 16 {
			return nil, errors.New("unikraft supports at most 16 exported LUNs")
		}
	}
	keys := []string{"uplink_device", "uplink_address", "uplink_gateway", "provider_address", "peer_address", "provider_mac", "peer_mac"}
	values := make([]string, len(keys))
	network := false
	for i, key := range keys {
		values[i] = take(key)
		network = network || values[i] != ""
	}
	if network {
		if values[0] != "0" {
			return nil, errors.New("unikraft's single pre-boot uplink must be device 0")
		}
		addresses := make([]netip.Addr, 4)
		for i := range addresses {
			address, err := netip.ParseAddr(values[i+1])
			if err != nil || !address.Is4() || address.IsUnspecified() || address.IsMulticast() || address.IsLoopback() {
				return nil, fmt.Errorf("invalid Unikraft %s", keys[i+1])
			}
			addresses[i] = address
		}
		subnet := netip.MustParsePrefix(UplinkSubnet)
		last := addresses[0].As4()[3]
		peerSubnet := netip.PrefixFrom(addresses[2], 30).Masked()
		if !subnet.Contains(addresses[0]) || last == 0 || last == 1 || last == 255 ||
			addresses[1].String() != UplinkGateway ||
			!peerSubnet.Contains(addresses[3]) || subnet.Contains(addresses[2]) ||
			addresses[2].As4()[3]%4 != 1 || addresses[3].As4()[3]%4 != 2 {
			return nil, errors.New("unikraft requires an uplink on diode-uplink and provider/peer host addresses 1/2 on a distinct /30")
		}
		macs := make([]net.HardwareAddr, 2)
		for i := range macs {
			mac, err := net.ParseMAC(values[i+5])
			if err != nil || len(mac) != 6 || mac[0]&1 != 0 || mac.String() == "00:00:00:00:00:00" {
				return nil, fmt.Errorf("invalid Unikraft %s", keys[i+5])
			}
			macs[i] = mac
		}
		if macs[0].String() == macs[1].String() {
			return nil, errors.New("unikraft provider and peer MACs must differ")
		}
		cfg.Network = &UnikraftNetwork{addresses[0], addresses[1], addresses[2], addresses[3], macs[0], macs[1]}
	}
	if len(params) != 0 || (cfg.Network == nil && len(cfg.LUNs) == 0) {
		return nil, errors.New("unikraft manifest has unknown parameters or enables no diode services")
	}
	if cfg.LiveStorage && len(cfg.LUNs) == 0 ||
		cfg.GCSRelay && (!cfg.LiveStorage || cfg.Network == nil) {
		return nil, errors.New("unikraft container services require live storage, boot exports and networking")
	}
	return cfg, nil
}
