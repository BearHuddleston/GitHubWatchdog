// Package logger provides a simple logging interface with verbosity control
package logger

import (
	"log"
)

// Logger is a custom logger with verbosity control
type Logger struct {
	verbose bool
}

// New creates a new logger with verbosity control
func New(verbose bool) *Logger {
	return &Logger{
		verbose: verbose,
	}
}

// Info logs informational messages that are always shown
func (l *Logger) Info(format string, v ...interface{}) {
	log.Printf(format, v...)
}

// Debug logs debug messages only when verbose mode is enabled
func (l *Logger) Debug(format string, v ...interface{}) {
	if l.verbose {
		log.Printf("[DEBUG] "+format, v...)
	}
}

// Error logs error messages
func (l *Logger) Error(format string, v ...interface{}) {
	log.Printf("[ERROR] "+format, v...)
}

// Warn logs warning messages
func (l *Logger) Warn(format string, v ...interface{}) {
	log.Printf("[WARN] "+format, v...)
}

// Fatal logs an error message and then exits the program
func (l *Logger) Fatal(format string, v ...interface{}) {
	log.Fatalf("[FATAL] "+format, v...)
}

// IsVerbose returns whether verbose logging is enabled
func (l *Logger) IsVerbose() bool {
	return l.verbose
}