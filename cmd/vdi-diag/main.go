// Package main is the entry point for the vdi-diag CLI tool.
package main

import (
	"os"

	"github.com/p2well/vdi-diag/cmd/vdi-diag/cmd"
)

func main() {
	if err := cmd.Execute(); err != nil {
		os.Exit(1)
	}
}
