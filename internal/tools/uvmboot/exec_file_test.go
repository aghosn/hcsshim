//go:build windows

package main

import (
	"flag"
	"os"
	"path/filepath"
	"testing"

	"github.com/urfave/cli"
)

func newExecTestContext(t *testing.T, args ...string) *cli.Context {
	t.Helper()

	set := flag.NewFlagSet("exec-test", flag.ContinueOnError)
	set.String(execCommandLineArgName, "", "")
	set.String(execFileArgName, "", "")
	if err := set.Parse(args); err != nil {
		t.Fatal(err)
	}
	return cli.NewContext(cli.NewApp(), set, nil)
}

func TestLoadExecCommandDirect(t *testing.T) {
	c := newExecTestContext(t, "-exec", "echo direct")

	command, err := loadExecCommand(c)
	if err != nil {
		t.Fatal(err)
	}
	if command != "echo direct" {
		t.Fatalf("command = %q, want %q", command, "echo direct")
	}
}

func TestLoadExecCommandFileNormalizesCRLF(t *testing.T) {
	path := filepath.Join(t.TempDir(), "inventory.sh")
	if err := os.WriteFile(path, []byte("echo one\r\necho two\r\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	c := newExecTestContext(t, "-exec-file", path)

	command, err := loadExecCommand(c)
	if err != nil {
		t.Fatal(err)
	}
	if command != "echo one\necho two\n" {
		t.Fatalf(
			"command = %q, want %q",
			command,
			"echo one\necho two\n",
		)
	}
}

func TestLoadExecCommandRejectsBothSources(t *testing.T) {
	c := newExecTestContext(
		t,
		"-exec",
		"echo direct",
		"-exec-file",
		"inventory.sh",
	)

	if _, err := loadExecCommand(c); err == nil {
		t.Fatal("expected mutually exclusive exec source error")
	}
}
