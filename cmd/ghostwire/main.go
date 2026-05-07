package main

import (
	"os"

	"github.com/ghostwire/ghostwire/internal/cli"
)

func main() {
	if err := cli.Execute(); err != nil {
		os.Exit(1)
	}
}
