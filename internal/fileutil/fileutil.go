package fileutil

import (
	"bufio"
	"os"
	"strings"
)

// LoadProcessedRepos reads a file and returns a map of processed repository IDs.
func LoadProcessedRepos(filename string) (map[string]bool, error) {
	file, err := os.Open(filename)
	if err != nil {
		if os.IsNotExist(err) {
			return make(map[string]bool), nil
		}
		return nil, err
	}
	defer file.Close()

	processed := make(map[string]bool)
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" {
			processed[line] = true
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return processed, nil
}

// WriteLineToFile appends a line to a file.
func WriteLineToFile(filename, line string) error {
	file, err := os.OpenFile(filename, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return err
	}
	defer file.Close()
	_, err = file.WriteString(line + "\n")
	return err
}

// AppendSuspiciousUser appends a suspicious username to its file.
func AppendSuspiciousUser(filename, username string) error {
	return WriteLineToFile(filename, username)
}

// AppendMaliciousRepo appends a malicious repository ID to its file.
func AppendMaliciousRepo(filename, repoID string) error {
	return WriteLineToFile(filename, repoID)
}

// AppendMaliciousStargazer appends a malicious stargazer's username to its file.
func AppendMaliciousStargazer(filename, username string) error {
	return WriteLineToFile(filename, username)
}

// AppendProcessedRepo appends a processed repository ID to its file.
func AppendProcessedRepo(filename, repoID string) error {
	return WriteLineToFile(filename, repoID)
}
