//go:build windows

package main

import "fmt"

func siblingOpenShellGuestCommand(busModule, vsockModule, bundle, role string, uplink *diodeUplink, dns []string) (string, error) {
	if role != diodeRole && role != workloadRole {
		return "", fmt.Errorf("unsupported OpenShell sibling role %q", role)
	}
	if (role == diodeRole) != (uplink != nil) {
		return "", fmt.Errorf("OpenShell requires an uplink on the diode only")
	}
	command := "set -eu; umask 022; insmod " + shellSingleQuote(busModule) + "; " +
		siblingVsockGuestModuleCommand(vsockModule, role) +
		"mkdir -p /run/openshell; " +
		"mount -t tmpfs -o exec,nosuid,nodev,size=768m,mode=0700 tmpfs /run/openshell; " +
		"tar -xf " + shellSingleQuote(bundle) + " -C /run/openshell; " +
		"mkdir -p /run/dtb-exec; "
	if role == diodeRole {
		if len(dns) == 0 {
			return "", fmt.Errorf("OpenShell diode requires DNS servers")
		}
		command += "ip link set lo up; " +
			guestWaitFor("up=; for n in /sys/class/net/*; do n=${n##*/}; "+
				"[ -e /sys/class/net/$n/device ] && up=$n; done; [ -n \"$up\" ]", "OpenShell uplink") +
			"ip addr add " + shellSingleQuote(uplink.address) + " dev \"$up\"; " +
			"ip link set \"$up\" up; ip route add default via " + shellSingleQuote(uplink.gateway) + " dev \"$up\"; " +
			(siblingNetConfig{dns: dns}).commandDNS() + "; "
	} else {
		command += (siblingNetConfig{dns: []string{"127.0.0.53"}}).commandDNS() + "; "
	}
	name := "workload"
	if role == diodeRole {
		name = "diode"
	}
	command += "/run/openshell/start.sh " + name
	return command, nil
}
