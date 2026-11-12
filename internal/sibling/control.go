//go:build windows

package sibling

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/Microsoft/hcsshim/internal/cmd"
	"github.com/Microsoft/hcsshim/internal/cow"
	"github.com/Microsoft/hcsshim/internal/log"
	"github.com/Microsoft/hcsshim/internal/uvm"
)

const exportParameters = "/sys/module/diode_storvsp/parameters/"

type commandRunner func(context.Context, string) (string, error)

// ExportControl is the live diode_storvsp control plane. No failure, including a
// canceled GCS request, is evidence that an export has been withdrawn.
type ExportControl struct {
	run  commandRunner
	gate chan struct{}
}

func NewExportControl(diode *uvm.UtilityVM) (*ExportControl, error) {
	if diode == nil || diode.OS() != "linux" {
		return nil, errors.New("sibling exports require a Linux diode")
	}
	return newExportControl(func(ctx context.Context, script string) (string, error) {
		return runGuest(ctx, diode, script)
	}), nil
}

func newExportControl(run commandRunner) *ExportControl {
	return &ExportControl{run: run, gate: make(chan struct{}, 1)}
}

// cmd.Cmd uses context.TODO for CreateProcess. Preserve its cancellation/stdio
// handling while binding the GCS create request itself to the operation context.
type contextHost struct {
	cow.ProcessHost
	ctx context.Context
}

func (h contextHost) CreateProcess(_ context.Context, settings interface{}) (cow.Process, error) {
	return h.ProcessHost.CreateProcess(h.ctx, settings)
}

func runGuest(ctx context.Context, vm *uvm.UtilityVM, script string) (string, error) {
	var out, stderr bytes.Buffer
	command := cmd.CommandContext(ctx, contextHost{vm, ctx}, "/bin/sh", "-ec", script)
	command.CopyAfterExitTimeout = time.Second
	command.Stdout, command.Stderr = &out, &stderr
	err := command.Run()
	if err != nil {
		return out.String(), fmt.Errorf("guest command: %w; stdout:\n%s\nstderr:\n%s",
			err, guestOutputTail(out.String()), guestOutputTail(stderr.String()))
	}
	return out.String(), nil
}

func guestOutputTail(output string) string {
	const limit = 16384
	if len(output) > limit {
		return "[earlier output truncated]\n" + output[len(output)-limit:]
	}
	return strings.TrimSpace(output)
}

func bootstrapCommand(stage, script string) string {
	diagnostics := `rc=$?; trap - EXIT; if [ "$rc" -ne 0 ]; then set +e; set +x; ` +
		`printf '%s\n' ` + Quote("sibling bootstrap failed: "+stage) + ` >&2; ` +
		`for file in /sys/bus/vmbus/drivers/sibling_bus/*-*/sibling_instance ` +
		`/sys/module/diode_storvsp/parameters/exports /run/gcs-relay.log; do ` +
		`if [ -r "$file" ]; then printf '\n=== %s ===\n' "$file" >&2; tail -n 40 "$file" >&2; fi; done; ` +
		`ls -l /sys/class/net >&2; ` +
		`for p in /sys/class/net/*; do ` +
		`printf '%s device=%s driver=%s\n' "$p" "$(readlink -f "$p/device")" "$(readlink -f "$p/device/driver")" >&2; done; ` +
		`dmesg | tail -n 60 >&2; fi; exit "$rc"`
	return "trap " + Quote(diagnostics) + " EXIT; set -x; " + script
}

func runBootstrapGuest(ctx context.Context, vm *uvm.UtilityVM, stage, script string) (string, error) {
	entry := log.G(ctx).WithField("stage", stage)
	entry.Info("sibling bootstrap starting")
	output, err := runGuest(ctx, vm, bootstrapCommand(stage, script))
	if err != nil {
		entry.WithError(err).Error("sibling bootstrap failed")
		return output, fmt.Errorf("%s: %w", stage, err)
	}
	entry.Info("sibling bootstrap complete")
	return output, nil
}

type export struct {
	token    uint64
	readOnly bool
	retiring bool
}

func parseExports(text string) (map[uint8]export, error) {
	exports := make(map[uint8]export)
	for _, line := range strings.Split(strings.TrimSpace(text), "\n") {
		if strings.TrimSpace(line) == "" {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) != 7 {
			return nil, fmt.Errorf("invalid diode export listing line %q", line)
		}
		lun, err := strconv.ParseUint(fields[0], 10, 8)
		if err != nil || lun == 255 {
			return nil, fmt.Errorf("invalid diode export LUN %q", fields[0])
		}
		token, err := strconv.ParseUint(fields[1], 10, 64)
		if err != nil {
			return nil, fmt.Errorf("invalid diode export token %q", fields[1])
		}
		if (fields[2] != "0" && fields[2] != "1") || (fields[5] != "0" && fields[5] != "1") {
			return nil, fmt.Errorf("invalid diode export flags in %q", line)
		}
		device := strings.Split(fields[3], ":")
		if len(device) != 2 {
			return nil, fmt.Errorf("invalid diode export device %q", fields[3])
		}
		for _, number := range []string{device[0], device[1], fields[4], fields[6]} {
			if _, err := strconv.ParseUint(number, 10, 64); err != nil {
				return nil, fmt.Errorf("invalid diode export number %q", number)
			}
		}
		if _, ok := exports[uint8(lun)]; ok {
			return nil, fmt.Errorf("duplicate diode export LUN %d", lun)
		}
		exports[uint8(lun)] = export{token: token, readOnly: fields[2] == "1", retiring: fields[5] == "1"}
	}
	return exports, nil
}

func (c *ExportControl) listing(ctx context.Context) (map[uint8]export, error) {
	text, err := c.run(ctx, "cat "+exportParameters+"exports")
	if err != nil {
		return nil, fmt.Errorf("cannot establish diode export state: %w", err)
	}
	return parseExports(text)
}

func (c *ExportControl) checkProvider(ctx context.Context) error {
	if _, err := c.run(ctx, "test -w "+exportParameters+"export_add && test -w "+exportParameters+"export_remove"); err != nil {
		return fmt.Errorf("diode provider does not support live exports: %w", err)
	}
	exports, err := c.listing(ctx)
	if err != nil {
		return err
	}
	root, ok := exports[0]
	if !ok || !root.readOnly || root.retiring {
		return errors.New("diode provider has no active read-only root LUN 0")
	}
	return nil
}

func (c *ExportControl) lock(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	select {
	case c.gate <- struct{}{}:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func validateExport(lun uint8, token uint64) error {
	if lun == 0 || lun == 255 || token == 0 {
		return errors.New("dynamic sibling exports require LUN 1..254 and a nonzero token; root LUN 0 is reserved")
	}
	return nil
}

func (c *ExportControl) Add(ctx context.Context, controller, lun uint, exportLUN uint8, token uint64, readOnly bool) error {
	if err := validateExport(exportLUN, token); err != nil {
		return err
	}
	resolve, err := RPDeviceCommand(controller, lun)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	if err := c.lock(ctx); err != nil {
		return err
	}
	defer func() { <-c.gate }()
	exports, err := c.listing(ctx)
	if err != nil {
		return err
	}
	if existing, ok := exports[exportLUN]; ok {
		if existing.token == token && existing.readOnly == readOnly && !existing.retiring {
			return nil
		}
		return fmt.Errorf("diode LUN %d is already owned or retiring", exportLUN)
	}
	ro := 0
	if readOnly {
		ro = 1
	}
	_, writeErr := c.run(ctx, resolve+fmt.Sprintf(
		`printf '%%s\n' "%d %d %d $storage_dev" >`+exportParameters+"export_add", exportLUN, ro, token))
	exports, err = c.listing(ctx)
	if err != nil {
		return errors.Join(writeErr, err)
	}
	if existing, ok := exports[exportLUN]; ok && existing.token == token &&
		existing.readOnly == readOnly && !existing.retiring {
		return nil
	}
	return errors.Join(writeErr, fmt.Errorf("diode export LUN %d token %d was not confirmed active", exportLUN, token))
}

func (c *ExportControl) Remove(ctx context.Context, lun uint8, token uint64) error {
	if err := validateExport(lun, token); err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	if err := c.lock(ctx); err != nil {
		return err
	}
	defer func() { <-c.gate }()
	exports, err := c.listing(ctx)
	if err != nil {
		return err
	}
	existing, ok := exports[lun]
	if !ok {
		return nil
	}
	if existing.token != token {
		return fmt.Errorf("refusing stale removal of diode LUN %d token %d (current %d)", lun, token, existing.token)
	}
	_, writeErr := c.run(ctx, fmt.Sprintf("printf '%%s\\n' '%d %d' >"+exportParameters+"export_remove", lun, token))
	for {
		exports, err = c.listing(ctx)
		if err != nil {
			return errors.Join(writeErr, err)
		}
		if current, ok := exports[lun]; !ok {
			return nil
		} else if current.token != token {
			return fmt.Errorf("diode LUN %d changed ownership during removal", lun)
		}
		select {
		case <-ctx.Done():
			return errors.Join(writeErr, fmt.Errorf("diode export still present; backing must remain attached: %w", ctx.Err()))
		case <-time.After(100 * time.Millisecond):
		}
	}
}
