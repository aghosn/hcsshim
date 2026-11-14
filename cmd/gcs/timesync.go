//go:build linux

package main

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/pkg/errors"
)

const timesyncPHCWaitBudget = 120 * time.Second

// timesyncWaitFromCommandLine accepts only one measured gcs.timesync_wait=1
// selector. Absence preserves immediate PHC lookup; explicit ambiguity fails.
func timesyncWaitFromCommandLine(commandLine string) (bool, error) {
	selected := false
	for _, field := range strings.Fields(commandLine) {
		key, value, _ := strings.Cut(field, "=")
		if key != "gcs.timesync_wait" {
			continue
		}
		if selected || value != "1" {
			return false, errors.New("gcs.timesync_wait requires exactly one value of 1")
		}
		selected = true
	}
	return selected, nil
}

// findTimesyncPHC finds the existing hyperv clock by name, without reading the
// clock or requiring a sample. A missing class/device is an appearance miss.
func findTimesyncPHC() (string, error) {
	entries, err := os.ReadDir("/sys/class/ptp")
	if os.IsNotExist(err) {
		return "", nil
	}
	if err != nil {
		return "", errors.Wrap(err, "failed to list PTP class directory")
	}
	for _, entry := range entries {
		path := filepath.Join("/sys/class/ptp", entry.Name(), "clock_name")
		name, err := os.ReadFile(path)
		if err != nil && !os.IsNotExist(err) {
			return "", errors.Wrapf(err, "failed to read clock name file at %s", path)
		}
		if string(name) == "hyperv\n" {
			return filepath.Join("/dev", entry.Name()), nil
		}
	}
	return "", nil
}

// timesyncPHC preserves ordinary immediate lookup and adds only a bounded
// appearance wait for the measured profile used by startTimeSyncService.
func timesyncPHC(wait bool) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timesyncPHCWaitBudget)
	defer cancel()
	for {
		device, err := findTimesyncPHC()
		if err != nil || device != "" {
			return device, err
		}
		if !wait {
			return "", errors.New("no PTP device found with name \"hyperv\\n\"")
		}
		timer := time.NewTimer(100 * time.Millisecond)
		select {
		case <-ctx.Done():
			timer.Stop()
			return "", errors.Wrap(ctx.Err(), "waiting for hyperv PHC appearance")
		case <-timer.C:
		}
	}
}

// startTimeSyncService starts chronyd asynchronously using the hyperv PHC.
// Selected workloads wait only for PHC appearance, never an initial sample,
// clock read or convergence. Configuration and restart behavior are unchanged.
func startTimeSyncService(wait bool) error {
	ptpDevPath, err := timesyncPHC(wait)
	if err != nil {
		return err
	}
	// chronyd config file taken from: https://docs.microsoft.com/en-us/azure/virtual-machines/linux/time-sync
	chronydConfigString := fmt.Sprintf("refclock PHC %s poll 3 dpoll -2 offset 0 stratum 2\nmakestep 0.1 -1\n", ptpDevPath)
	chronydConfPath := "/tmp/chronyd.conf"
	if err := os.WriteFile(chronydConfPath, []byte(chronydConfigString), 0644); err != nil {
		return errors.Wrapf(err, "failed to create chronyd conf file %s", chronydConfPath)
	}

	// Foreground chronyd avoids double-fork exits confusing the restart monitor.
	go runWithRestartMonitor("chronyd", "-n", "-f", chronydConfPath)
	return nil
}
