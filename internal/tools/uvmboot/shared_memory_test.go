//go:build windows

package main

import (
	"strings"
	"testing"

	hcsschema "github.com/Microsoft/hcsshim/internal/hcs/schema2"
)

func TestSharedMemorySectionNames(t *testing.T) {
	win32Name, hcsName, err := sharedMemorySectionNames("hcsshim-test", 3)
	if err != nil {
		t.Fatal(err)
	}
	if win32Name != "hcsshim-test" {
		t.Fatalf("Win32 section name = %q, want %q", win32Name, "hcsshim-test")
	}
	if hcsName != `\Sessions\3\BaseNamedObjects\hcsshim-test` {
		t.Fatalf(
			"HCS section name = %q, want %q",
			hcsName,
			`\Sessions\3\BaseNamedObjects\hcsshim-test`,
		)
	}
}

func TestSharedMemorySectionNamesRejectsPath(t *testing.T) {
	_, _, err := sharedMemorySectionNames(`Global\hcsshim-test`, 3)
	if err == nil {
		t.Fatal("expected namespaced section name to be rejected")
	}
}

func TestShellSingleQuote(t *testing.T) {
	got := shellSingleQuote("/run/module's/hcs_shmem_diag.ko")
	want := `'/run/module'"'"'s/hcs_shmem_diag.ko'`
	if got != want {
		t.Fatalf("shellSingleQuote() = %q, want %q", got, want)
	}
}

func TestSiblingVsockReadyCommand(t *testing.T) {
	for _, test := range []struct {
		role  string
		ready string
	}{
		{diodeRole, "sibling_vmbus: stock hv_sock ready role=diode local_cid=4"},
		{workloadRole, "sibling_vmbus: stock hv_sock ready role=workload local_cid=3"},
	} {
		t.Run(test.role, func(t *testing.T) {
			command := siblingVsockReadyCommand(test.role)
			for _, expected := range []string{
				"/sys/bus/vmbus/drivers/hv_sock",
				"exit 1",
				"[ $i -le 30 ]",
				`echo "` + test.ready,
			} {
				if !strings.Contains(command, expected) {
					t.Fatalf("command %q does not contain %q", command, expected)
				}
			}
			if strings.Contains(command, "insmod") || strings.Contains(command, "diode_vsock") {
				t.Fatal("stock socket setup must not load the legacy transport")
			}
		})
	}
}

func TestSiblingGuestDiscoversInstanceOnce(t *testing.T) {
	for _, role := range []string{diodeRole, workloadRole} {
		command := siblingBusGuestModuleCommand("/run/sibling_bus.ko",
			"", role, siblingNetConfig{ifName: "dvsc0"}, nil)
		if strings.Count(command, "sb_instance=$1;") != 1 {
			t.Fatal("guest setup must discover its bus exactly once")
		}
		for _, expected := range []string{"/sibling_instance", `grep -q 'ready=1'`,
			"sibling_vmbus: protocol version mismatch"} {
			if !strings.Contains(command, expected) {
				t.Fatalf("guest setup missing %q", expected)
			}
		}
		if role == workloadRole && strings.Index(command, "sb_bus=${1#*=}") >
			strings.Index(command, "bus${sb_bus}-relid*") {
			t.Fatal("bus discovery must precede NIC selection")
		}
	}
}

func TestStockPeerNICIsSelectedByBusOwnership(t *testing.T) {
	command := siblingStockNICCommand("dvsc0")
	for _, expected := range []string{
		"bus${sb_bus}-relid*", "hv_netvsc",
		`[ "$sb_count" -eq 1 ]`, `ip link set "$sb_net" name 'dvsc0'`,
		"stock hv_netvsc registered", "peer NIC rename failed",
	} {
		if !strings.Contains(command, expected) {
			t.Fatalf("stock NIC setup missing %q", expected)
		}
	}
	if siblingNetModuleName(workloadRole) != "" || siblingNetModuleName(diodeRole) != "diode_netvsp.ko" {
		t.Fatal("only the provider needs an out-of-tree network module")
	}
}

func TestSiblingGuestKernelLogAllowsNoMatchingMessages(t *testing.T) {
	for _, role := range []string{diodeRole, workloadRole} {
		command := siblingBusGuestModuleCommand("/run/sibling_bus.ko",
			"", role, siblingNetConfig{ifName: "dvsc0"}, nil)
		if !strings.HasSuffix(command,
			`dmesg | grep -E 'diode_net|hv_netvsc' || [ "$?" -eq 1 ]`) {
			t.Fatal("final diagnostic grep must accept no matches without suppressing grep errors")
		}
	}
}

func TestStockSocketProofUsesActualPeerAndVerifiedToolExit(t *testing.T) {
	for _, role := range []string{diodeRole, workloadRole} {
		command := siblingVsockProofCommand(role)
		for _, expected := range []string{
			`"$sb_local"`, `connect "$sb_peer"`, `wait "$sb_vsock_pid" ||`,
			"listening on vsock port", "[ $i -le 30 ]", "exit 1",
			"stock hv_sock payload role=" + siblingRoleName(role) + " ok",
		} {
			if !strings.Contains(command, expected) {
				t.Fatalf("stock socket proof missing %q", expected)
			}
		}
		if strings.Contains(command, "insmod") {
			t.Fatal("payload proof must use the built-in transport")
		}
	}
}

func TestSiblingFailuresIncludeDeviceStateAndUnfilteredKernelLog(t *testing.T) {
	for _, command := range []string{
		guestWaitFor("false", "test"),
		siblingVsockProofCommand(diodeRole),
		siblingVsockProofCommand(workloadRole),
	} {
		for _, expected := range []string{
			"sibling_vmbus: failure diagnostics",
			"/sys/class/net/*", "/sys/bus/vmbus/devices/bus*-relid*",
			`readlink "$p/driver"`, "in_read_index", "out_write_index",
			"sibling_instance", "sibling_stats", "dmesg >&2 || true",
		} {
			if !strings.Contains(command, expected) {
				t.Fatalf("failure diagnostics missing %q", expected)
			}
		}
		if strings.Contains(command, "dmesg | grep") {
			t.Fatal("failure diagnostics must not hide stock-driver probe errors")
		}
	}
}

func TestSiblingVsockToolStagedOnExecFilesystem(t *testing.T) {
	for _, expected := range []string{
		"mount -t tmpfs -o exec",
		"cp /run/diode-vsock-test/diode_vsock_test /run/dtb-exec/vsock-test",
		"chmod 755 /run/dtb-exec/vsock-test ||",
		"diode_vsock: tool staging failed",
	} {
		if !strings.Contains(siblingWorkloadStage, expected) {
			t.Fatalf("tool staging command does not contain %q", expected)
		}
	}
}

func TestBaselineNICDoesNotRequireSiblingVsock(t *testing.T) {
	command := baselineNICUp(&diodeUplink{
		address: "172.31.250.2/24",
		gateway: "172.31.250.1",
	})
	if strings.Contains(command, "diode-vsock") || strings.Contains(command, "vsock-test") {
		t.Fatal("baseline NIC setup must not require sibling vsock tools")
	}
}

func TestSharedMemoryGuestModuleCommandConvertsGPN(t *testing.T) {
	command, err := sharedMemoryGuestModuleCommand(
		"/run/hcs_shmem_diag.ko",
		hcsschema.SharedMemoryRegion{
			SectionName: "section",
			Length:      0x100000,
		},
		hcsschema.SharedMemoryRegionInfo{
			SectionName:          "section",
			GuestPhysicalAddress: 0x20000,
		},
		"a",
		siblingEventModuleArgs(hcsschema.SiblingCommunicationRouteInfo{
			TargetVP:             0,
			TargetSINT:           3,
			EventFlagNumber:      11,
			OutboundConnectionID: 0x100015,
		}),
	)
	if err != nil {
		t.Fatal(err)
	}
	for _, expected := range []string{
		"gpa=0x20000000",
		"length=0x100000",
		"decrypted=1",
		"role='a' signal_conn=0x100015 rx_vp=0 rx_sint=3 rx_flag=11;",
	} {
		if !strings.Contains(command, expected) {
			t.Fatalf("command %q does not contain %q", command, expected)
		}
	}
}

func TestSharedMemoryGuestModuleCommandRejectsDifferentSection(t *testing.T) {
	_, err := sharedMemoryGuestModuleCommand(
		"/run/hcs_shmem_diag.ko",
		hcsschema.SharedMemoryRegion{
			SectionName: "expected",
			Length:      0x1000,
		},
		hcsschema.SharedMemoryRegionInfo{
			SectionName:          "other",
			GuestPhysicalAddress: 0x20000,
		},
		"single",
		"",
	)
	if err == nil {
		t.Fatal("expected mismatched section to fail")
	}
}

func TestSharedMemoryProofRole(t *testing.T) {
	for _, test := range []struct {
		id   string
		role string
	}{
		{id: "uvmboot-0", role: "a"},
		{id: "uvmboot-1", role: "b"},
	} {
		role, err := sharedMemoryProofRole(test.id)
		if err != nil {
			t.Fatalf("sharedMemoryProofRole(%q): %v", test.id, err)
		}
		if role != test.role {
			t.Fatalf(
				"sharedMemoryProofRole(%q) = %q, want %q",
				test.id,
				role,
				test.role,
			)
		}
	}
}

func TestSharedMemoryProofRoleRejectsUnexpectedID(t *testing.T) {
	if _, err := sharedMemoryProofRole("uvmboot-2"); err == nil {
		t.Fatal("expected unexpected UVM ID to fail")
	}
}
