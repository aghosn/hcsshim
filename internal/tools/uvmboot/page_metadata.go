//go:build windows

package main

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/urfave/cli"
)

const pageMetadataOutputArgName = "page-metadata-output"
const pageMetadataCollector = "collect-page-metadata.sh"
const pageMetadataGuestResults = "/run/page-metadata-results"

func newPageMetadataOutput(root string) (string, error) {
	if !filepath.IsAbs(root) || strings.HasPrefix(root, `\\`) {
		return "", fmt.Errorf("page metadata output must be an existing local absolute directory")
	}
	info, err := os.Lstat(root)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return "", fmt.Errorf("page metadata output must be an existing directory, not a link: %s", root)
	}
	run, err := os.MkdirTemp(root, "page-metadata-")
	if err != nil {
		return "", err
	}
	for _, role := range []string{"diode", "workload"} {
		path := filepath.Join(run, role)
		if err := os.Mkdir(path, 0700); err != nil {
			return "", err
		}
		if err := os.WriteFile(filepath.Join(path, "run.txt"),
			[]byte("run="+filepath.Base(run)+"\nrole="+role+"\n"), 0600); err != nil {
			return "", err
		}
		fmt.Printf("page metadata results: role=%s host=%s guest=%s\n", role, path, pageMetadataGuestResults)
	}
	return run, nil
}

func preparePageMetadataOutput(c *cli.Context) error {
	if !c.IsSet(pageMetadataOutputArgName) {
		return nil
	}
	if !useGCS || !c.Bool(siblingInteractiveArgName) || !c.Bool(siblingDiodeUplinkArgName) ||
		c.GlobalInt(countArgName) != 2 || c.GlobalInt(parallelArgName) != 2 ||
		c.String(siblingBusGuestModuleArgName) == "" ||
		c.String(siblingOpenShellBundleArgName) != "" || c.String(unikraftPackageArgName) != "" ||
		c.Bool(siblingGCSRelayArgName) || c.Bool(validateStorageBackendsArgName) {
		return fmt.Errorf("--%s requires an interactive Linux diode/workload pair without --%s", pageMetadataOutputArgName, siblingGCSRelayArgName)
	}
	run, err := newPageMetadataOutput(c.String(pageMetadataOutputArgName))
	if err != nil {
		return err
	}
	return c.Set(pageMetadataOutputArgName, run)
}

type pageMetadataSharer interface {
	Share(context.Context, string, string, bool) error
}

func stagePageMetadata(ctx context.Context, c *cli.Context, vm pageMetadataSharer, role string) (string, error) {
	source := filepath.Join(filepath.Dir(c.String(siblingBusGuestModuleArgName)), pageMetadataCollector)
	if err := vm.Share(ctx, source, "/run/page-metadata-tools", true); err != nil {
		return "", fmt.Errorf("share page metadata collector: %w", err)
	}
	if root := c.String(pageMetadataOutputArgName); root != "" {
		name := "diode"
		if role == workloadRole {
			name = "workload"
		} else if role != diodeRole {
			return "", fmt.Errorf("invalid page metadata role %q", role)
		}
		if err := vm.Share(ctx, filepath.Join(root, name), pageMetadataGuestResults, false); err != nil {
			return "", fmt.Errorf("share requested page metadata results: %w", err)
		}
	}
	return "cp /run/page-metadata-tools/" + pageMetadataCollector + " /run/dtb-exec/" +
		pageMetadataCollector + " && chmod 755 /run/dtb-exec/" + pageMetadataCollector + " || exit 1; ", nil
}
