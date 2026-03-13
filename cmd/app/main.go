package main

import (
	"fmt"
	"log"
	"os"

	"github.com/arkouda/github/GitHubWatchdog/internal/cli"
)

func main() {
	log.SetFlags(log.LstdFlags | log.Lshortfile)

	if err := cli.Run(os.Args[1:], os.Stdout, os.Stderr); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
