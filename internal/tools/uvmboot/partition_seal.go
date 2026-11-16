//go:build windows

// Copyright (c) Microsoft Corporation. All rights reserved.

package main

import (
	"errors"
	"fmt"

	"github.com/Microsoft/hcsshim/internal/sibling"
	"github.com/urfave/cli"
)

// runSiblingSeal requests one runtime control from the existing privileged role
// owner. App.Before enforces elevation; no guest/console or VM creation is used.
func runSiblingSeal(c *cli.Context) error {
	if c.NArg() != 1 || !c.IsSet("mask") {
		return errors.New("usage: seal --mask <uint64> workload|diode (explicit mask required)")
	}
	result, err := sibling.RequestPartitionSeal(c.Args().First(), c.Uint64("mask"))
	if result != nil {
		fmt.Printf("partition seal: role=%s vm=%s mask=%d mask_hex=%#016x outcome=%s dispatched=%t error=%q\n",
			result.Role, result.VMID, result.Mask, result.Mask, result.Outcome, result.Dispatched, result.Error)
	}
	return err
}

var siblingSealCommand = cli.Command{
	Name:      "seal",
	Usage:     "Seal a running protected sibling role at a user-selected time",
	ArgsUsage: "workload|diode",
	Flags:     []cli.Flag{cli.Uint64Flag{Name: "mask", Usage: "Explicit uint64 partition seal mask, including zero"}},
	Action:    runSiblingSeal,
}
