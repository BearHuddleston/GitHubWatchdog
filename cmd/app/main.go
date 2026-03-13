package main

import (
	"errors"
	"fmt"
	"log"
	"os"

	"github.com/arkouda/github/GitHubWatchdog/internal/cli"
)

func main() {
	log.SetFlags(log.LstdFlags | log.Lshortfile)

	if err := cli.Run(os.Args[1:], os.Stdout, os.Stderr); err != nil {
		var withCode interface{ ExitCode() int }
		if errors.As(err, &withCode) {
			if err.Error() != "" {
				fmt.Fprintln(os.Stderr, err)
			}
			os.Exit(withCode.ExitCode())
		}
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
