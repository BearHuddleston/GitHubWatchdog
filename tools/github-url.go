package main

import (
	"bufio"
	"fmt"
	"os"
	"strings"
)

func ProcessSuspiciousUsers(inputPath, outputPath string) error {
	inputFile, err := os.Open(inputPath)
	if err != nil {
		return fmt.Errorf("failed to open input file: %w", err)
	}
	defer inputFile.Close()

	outputFile, err := os.Create(outputPath)
	if err != nil {
		return fmt.Errorf("failed to create output file: %w", err)
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
		fullURL := "1. [" + line + "](https://github.com/" + line + ")"
		_, err := writer.WriteString(fullURL + "\n")
		if err != nil {
			return fmt.Errorf("failed to write to output file: %w", err)
		}
	}

	if err := scanner.Err(); err != nil {
		return fmt.Errorf("error reading input file: %w", err)
	}
	return nil
}

// Example usage
func main() {
	inputPath := "../suspicious_users.txt"
	outputPath := "../bark/README.md"
	if err := ProcessSuspiciousUsers(inputPath, outputPath); err != nil {
		fmt.Println("Error:", err)
		os.Exit(1)
	}
	fmt.Println("Parsed URLs written to", outputPath)
}
