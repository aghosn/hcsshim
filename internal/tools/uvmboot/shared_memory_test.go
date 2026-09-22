//go:build windows

package main

import "testing"

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
