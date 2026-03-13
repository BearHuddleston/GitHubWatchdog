package main

import (
	"bufio"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

func processSuspiciousUsers(inputPath, outputPath string) error {
	inputFile, err := os.Open(inputPath)
	if err != nil {
		return fmt.Errorf("opening input file: %w", err)
	}
	defer inputFile.Close()

	if err := os.MkdirAll(filepath.Dir(outputPath), 0755); err != nil {
		return fmt.Errorf("creating output directory: %w", err)
	}

	outputFile, err := os.Create(outputPath)
	if err != nil {
		return fmt.Errorf("creating output file: %w", err)
	}
	defer outputFile.Close()

	scanner := bufio.NewScanner(inputFile)
	writer := bufio.NewWriter(outputFile)
	defer writer.Flush()

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}

		if _, err := fmt.Fprintf(writer, "1. [%s](https://github.com/%s)\n", line, line); err != nil {
			return fmt.Errorf("writing output line: %w", err)
		}
	}

	if err := scanner.Err(); err != nil {
		return fmt.Errorf("reading input file: %w", err)
	}

	return nil
}

func main() {
	inputPath := flag.String("input", "malicious_stargazers.txt", "Path to the newline-delimited username list")
	outputPath := flag.String("output", "./bark/malicious_stargazers/README.md", "Path to write the generated Markdown list")
	flag.Parse()

	if err := processSuspiciousUsers(*inputPath, *outputPath); err != nil {
		fmt.Println("Error:", err)
		os.Exit(1)
	}

	fmt.Println("Parsed URLs written to", *outputPath)
}
