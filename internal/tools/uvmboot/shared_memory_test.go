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

func TestSiblingVsockGuestModuleCommand(t *testing.T) {
	for _, test := range []struct {
		role  string
		ready string
	}{
		{diodeRole, "diode_vsock: vsock up: role=diode local_cid=4"},
		{workloadRole, "diode_vsock: vsock up: role=workload local_cid=3"},
	} {
		t.Run(test.role, func(t *testing.T) {
			command := siblingVsockGuestModuleCommand("/run/module's/diode_vsock.ko", test.role)
			for _, expected := range []string{
				`insmod '/run/module'"'"'s/diode_vsock.ko' diode_cid=4 workload_cid=3 ||`,
				"exit 1",
				"until dmesg | grep -qF '" + test.ready + "'",
				"[ $i -le 30 ]",
				"echo '" + test.ready + "'",
			} {
				if !strings.Contains(command, expected) {
					t.Fatalf("command %q does not contain %q", command, expected)
				}
			}
		})
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
