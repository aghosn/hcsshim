//go:build windows

package main

import (
	"strings"
	"testing"
)

func TestOpenShellWorkloadHasOnlySiblingVsock(t *testing.T) {
	command, err := siblingOpenShellGuestCommand(
		"/bus.ko", "/vsock.ko", "/bundle's.tar", workloadRole, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, required := range []string{
		"set -eu;", "umask 022;", "insmod '/bus.ko'", "insmod '/vsock.ko'",
		"local_cid=3", "exec,nosuid,nodev,size=768m,mode=0700",
		"127.0.0.53",
		`tar -xf '/bundle'"'"'s.tar'`, "/run/openshell/start.sh workload",
	} {
		if !strings.Contains(command, required) {
			t.Fatalf("missing %q in %s", required, command)
		}
	}
	for _, forbidden := range []string{
		"diode_netvsc", "diode_netvsp", "ip addr", "ip route",
		"MASQUERADE", "ip_forward", `"$dtb"`, "iperf",
	} {
		if strings.Contains(command, forbidden) {
			t.Fatalf("OpenShell workload must not include %q", forbidden)
		}
	}
}

func TestOpenShellDiodeHasUplinkWithoutNAT(t *testing.T) {
	command, err := siblingOpenShellGuestCommand(
		"/bus.ko", "/vsock.ko", "/bundle.tar", diodeRole,
		&diodeUplink{address: "172.31.250.2/24", gateway: "172.31.250.1"}, []string{"1.1.1.1"})
	if err != nil {
		t.Fatal(err)
	}
	for _, required := range []string{
		"local_cid=4", "ip link set lo up", "ip addr add '172.31.250.2/24'",
		"ip route add default via '172.31.250.1'", "nameserver",
		"/run/openshell/start.sh diode",
	} {
		if !strings.Contains(command, required) {
			t.Fatalf("missing %q in %s", required, command)
		}
	}
	for _, forbidden := range []string{"MASQUERADE", "ip_forward", "diode_netvsp", "10.200.0."} {
		if strings.Contains(command, forbidden) {
			t.Fatalf("OpenShell diode must not include %q", forbidden)
		}
	}
}

func TestOpenShellRejectsWrongRoleOrUplink(t *testing.T) {
	for _, test := range []struct {
		role   string
		uplink *diodeUplink
		dns    []string
	}{
		{"unknown", nil, nil},
		{diodeRole, nil, nil},
		{workloadRole, &diodeUplink{}, nil},
		{diodeRole, &diodeUplink{}, nil},
	} {
		if _, err := siblingOpenShellGuestCommand("/bus", "/vsock", "/bundle", test.role, test.uplink, test.dns); err == nil {
			t.Fatalf("expected rejection for %+v", test)
		}
	}
}
