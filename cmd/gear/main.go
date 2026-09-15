package main

import (
	"fmt"
	"os"

	"github.com/gear/engine/internal/cli"
)

const usage = `gear - secret management tool

Usage:
  gear <command> [options]

Commands:
  init    Initialize the system (generate Master Key, create admin account)
  serve   Start the HTTPS API server

Run 'gear <command> --help' for more information on a command.
`

func main() {
	if len(os.Args) < 2 {
		fmt.Fprint(os.Stderr, usage)
		os.Exit(1)
	}

	switch os.Args[1] {
	case "init":
		if err := cli.RunInit(os.Args[2:]); err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			os.Exit(1)
		}
	case "serve":
		if err := cli.RunServe(os.Args[2:]); err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			os.Exit(1)
		}
	case "--help", "-h", "help":
		fmt.Print(usage)
	default:
		fmt.Fprintf(os.Stderr, "unknown command: %s\n\n%s", os.Args[1], usage)
		os.Exit(1)
	}
}
