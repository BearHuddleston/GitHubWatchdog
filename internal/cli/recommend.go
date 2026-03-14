package cli

import (
	"fmt"
	"io"
	"regexp"
	"strconv"
	"strings"
	"time"
)

var (
	repoRefPattern    = regexp.MustCompile(`\b[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+\b`)
	quotedDatePattern = regexp.MustCompile(`\b\d{4}-\d{2}-\d{2}\b`)
	lastDaysPattern   = regexp.MustCompile(`\blast\s+(\d+)\s+days?\b`)
	lastHoursPattern  = regexp.MustCompile(`\blast\s+(\d+)\s+hours?\b`)
	userPattern       = regexp.MustCompile(`\b(?:user|username)\s+@?([A-Za-z0-9](?:[A-Za-z0-9-]{0,38}))\b`)
)

type recommendation struct {
	Prompt             string                   `json:"prompt"`
	ParsedIntent       recommendationIntent     `json:"parsed_intent"`
	Command            string                   `json:"command"`
	Subcommand         string                   `json:"subcommand,omitempty"`
	Confidence         string                   `json:"confidence"`
	FollowUpNeeded     bool                     `json:"follow_up_needed"`
	Assumptions        []string                 `json:"assumptions,omitempty"`
	Warnings           []string                 `json:"warnings,omitempty"`
	ResolvedTimeWindow *recommendationTimeRange `json:"resolved_time_window,omitempty"`
	Invocations        []recommendedInvocation  `json:"invocations"`
}

type recommendationIntent struct {
	TargetType string   `json:"target_type"`
	Targets    []string `json:"targets,omitempty"`
	Mode       string   `json:"mode"`
	Activity   string   `json:"activity,omitempty"`
}

type recommendationTimeRange struct {
	Start string `json:"start,omitempty"`
	End   string `json:"end,omitempty"`
}

type recommendedInvocation struct {
	Argv         []string `json:"argv"`
	ShellCommand string   `json:"shell_command"`
}

type resolvedTaskWindow struct {
	createdSince  string
	createdBefore string
	updatedSince  string
	updatedBefore string
	start         time.Time
	end           time.Time
}

func recommendTask(prompt string, now time.Time) recommendation {
	prompt = strings.TrimSpace(prompt)
	lowered := strings.ToLower(prompt)
	rec := recommendation{
		Prompt: prompt,
		ParsedIntent: recommendationIntent{
			Mode: "scan",
		},
		Confidence: "medium",
	}

	if prompt == "" {
		rec.Command = "capabilities"
		rec.FollowUpNeeded = true
		rec.Warnings = []string{"No task prompt was provided."}
		rec.Assumptions = []string{"Defaulted to capabilities because no executable task was described."}
		rec.Invocations = []recommendedInvocation{buildInvocation("githubwatchdog", "-quiet", "capabilities")}
		rec.ParsedIntent.Mode = "discover"
		return rec
	}

	if strings.Contains(lowered, "checkpoint") {
		return recommendCheckpointTask(prompt, lowered)
	}

	repoTargets := uniqueStrings(repoRefPattern.FindAllString(prompt, -1))
	userTargets := uniqueStrings(extractUserTargets(prompt))
	allTargets := append(append([]string(nil), repoTargets...), userTargets...)

	activity := inferActivity(lowered)
	window := resolveTaskWindow(prompt, lowered, now, activity)

	format := "json"
	if strings.Contains(lowered, "stream") || strings.Contains(lowered, "ndjson") || strings.Contains(lowered, "batch") || strings.Contains(lowered, "many") || len(allTargets) > 1 {
		format = "ndjson"
	}
	persist := wantsPersistence(lowered)
	failOnFindings := wantsFailOnFindings(lowered)

	switch {
	case len(allTargets) > 1:
		rec.Command = "verdict"
		rec.ParsedIntent.TargetType = "mixed"
		rec.ParsedIntent.Targets = allTargets
		rec.ParsedIntent.Mode = "batch"
		rec.Confidence = "high"
		rec.Assumptions = append(rec.Assumptions, "Batch verdict mode expects newline-delimited input via stdin or a file.")
		argv := []string{"githubwatchdog", "-quiet", "verdict", "--input", "-", "--format", format}
		if !persist {
			argv = append(argv, "--persist=false")
		}
		if failOnFindings {
			argv = append(argv, "--fail-on-findings")
		}
		argv = append(argv, "--continue-on-error")
		rec.Invocations = []recommendedInvocation{buildBatchInvocation(argv, allTargets)}
	case len(repoTargets) == 1 && len(userTargets) == 0:
		rec.Command = "repo"
		rec.ParsedIntent.TargetType = "repo"
		rec.ParsedIntent.Targets = repoTargets
		rec.Confidence = "high"
		argv := []string{"githubwatchdog", "-quiet", "repo", repoTargets[0], "--format", format}
		if !persist {
			argv = append(argv, "--persist=false")
		}
		if wantsSummary(lowered) || format != "text" {
			argv = append(argv, "--summary")
		}
		if failOnFindings {
			argv = append(argv, "--fail-on-findings")
		}
		rec.Invocations = []recommendedInvocation{buildInvocation(argv...)}
	case len(userTargets) == 1 && len(repoTargets) == 0:
		rec.Command = "user"
		rec.ParsedIntent.TargetType = "user"
		rec.ParsedIntent.Targets = userTargets
		rec.Confidence = "high"
		argv := []string{"githubwatchdog", "-quiet", "user", userTargets[0], "--format", format}
		if !persist {
			argv = append(argv, "--persist=false")
		}
		if wantsSummary(lowered) || format != "text" {
			argv = append(argv, "--summary")
		}
		if failOnFindings {
			argv = append(argv, "--fail-on-findings")
		}
		rec.Invocations = []recommendedInvocation{buildInvocation(argv...)}
	case strings.Contains(lowered, "verdict"):
		rec.Command = "verdict"
		rec.ParsedIntent.TargetType = "ambiguous"
		rec.FollowUpNeeded = true
		rec.Warnings = append(rec.Warnings, "No explicit repo or user target was found in the prompt.")
		rec.Invocations = []recommendedInvocation{buildInvocation("githubwatchdog", "-quiet", "capabilities")}
	default:
		rec.Command = "search"
		rec.ParsedIntent.TargetType = "repo-search"
		rec.ParsedIntent.Activity = activity
		rec.Confidence = "high"
		query := inferQuery(lowered)
		argv := []string{"githubwatchdog", "-quiet", "search", "--query", query, "--activity", activity, "--format", format}
		argv = append(argv, windowFlags(window)...)
		if !persist {
			argv = append(argv, "--persist=false")
		}
		if strings.Contains(lowered, "flagged") || strings.Contains(lowered, "suspicious only") {
			argv = append(argv, "--only-flagged")
		}
		if failOnFindings {
			argv = append(argv, "--fail-on-findings")
		}
		if format == "ndjson" && !strings.Contains(lowered, "include skipped") {
			argv = append(argv, "--include-skipped=false")
		}
		rec.Invocations = []recommendedInvocation{buildInvocation(argv...)}
	}

	if !window.start.IsZero() || !window.end.IsZero() {
		rec.ResolvedTimeWindow = &recommendationTimeRange{}
		if !window.start.IsZero() {
			rec.ResolvedTimeWindow.Start = window.start.Format(time.RFC3339)
		}
		if !window.end.IsZero() {
			rec.ResolvedTimeWindow.End = window.end.Format(time.RFC3339)
		}
	}
	if activity != "" {
		rec.ParsedIntent.Activity = activity
	}
	if len(rec.Invocations) == 0 {
		rec.Command = "capabilities"
		rec.FollowUpNeeded = true
		rec.Warnings = append(rec.Warnings, "Could not produce a concrete invocation from the prompt.")
		rec.Invocations = []recommendedInvocation{buildInvocation("githubwatchdog", "-quiet", "capabilities")}
	}
	return rec
}

func recommendCheckpointTask(prompt, lowered string) recommendation {
	rec := recommendation{
		Prompt:     prompt,
		Command:    "checkpoints",
		Confidence: "high",
		ParsedIntent: recommendationIntent{
			Mode:       "checkpoint",
			TargetType: "checkpoint",
		},
	}

	subcommand := "list"
	switch {
	case strings.Contains(lowered, "export"):
		subcommand = "export"
	case strings.Contains(lowered, "import"):
		subcommand = "import"
	case strings.Contains(lowered, "delete"), strings.Contains(lowered, "remove"):
		subcommand = "delete"
	case strings.Contains(lowered, "show"), strings.Contains(lowered, "inspect"):
		subcommand = "show"
	case strings.Contains(lowered, "list"):
		subcommand = "list"
	}
	rec.Subcommand = subcommand
	rec.Invocations = []recommendedInvocation{buildInvocation("githubwatchdog", "-quiet", "checkpoints", subcommand)}
	if subcommand == "import" {
		rec.Assumptions = append(rec.Assumptions, "Import expects --input <path|-> and JSON checkpoint payloads.")
	}
	return rec
}

func resolveTaskWindow(prompt, lowered string, now time.Time, activity string) resolvedTaskWindow {
	now = now.In(time.Local)
	window := resolvedTaskWindow{}
	preferDateOnly := false
	dates := quotedDatePattern.FindAllString(prompt, -1)
	if len(dates) >= 2 {
		window.start = mustParseLocalDate(dates[0], now.Location())
		window.end = mustParseLocalDate(dates[1], now.Location()).Add(24*time.Hour - time.Second)
	} else if len(dates) == 1 {
		window.start = mustParseLocalDate(dates[0], now.Location())
		preferDateOnly = true
	}

	if matches := lastDaysPattern.FindStringSubmatch(lowered); len(matches) == 2 {
		count, _ := strconv.Atoi(matches[1])
		window.start = startOfDay(now.AddDate(0, 0, -count))
		window.end = now
		preferDateOnly = true
	} else if matches := lastHoursPattern.FindStringSubmatch(lowered); len(matches) == 2 {
		count, _ := strconv.Atoi(matches[1])
		window.start = now.Add(-time.Duration(count) * time.Hour)
		window.end = now
	} else if strings.Contains(lowered, "yesterday") {
		window.start = startOfDay(now.AddDate(0, 0, -1))
		window.end = endOfDay(now.AddDate(0, 0, -1))
		preferDateOnly = true
	} else if strings.Contains(lowered, "today") {
		window.start = startOfDay(now)
		window.end = now
		preferDateOnly = true
	}

	dateStart := ""
	dateEnd := ""
	if !window.start.IsZero() && (preferDateOnly || (isWholeDayBoundary(window.start) && (window.end.IsZero() || isWholeDayBoundary(window.end) || window.end.Equal(endOfDay(window.end))))) {
		dateStart = window.start.Format(time.DateOnly)
		if !window.end.IsZero() {
			dateEnd = window.end.In(window.start.Location()).Format(time.DateOnly)
		}
	}

	switch activity {
	case "created":
		window.createdSince = firstNonEmpty(dateStart, formatSearchMoment(window.start))
		window.createdBefore = firstNonEmpty(dateEnd, formatSearchMoment(window.end))
	case "either":
		valueSince := firstNonEmpty(dateStart, formatSearchMoment(window.start))
		valueBefore := firstNonEmpty(dateEnd, formatSearchMoment(window.end))
		window.createdSince = valueSince
		window.createdBefore = valueBefore
		window.updatedSince = valueSince
		window.updatedBefore = valueBefore
	default:
		window.updatedSince = firstNonEmpty(dateStart, formatSearchMoment(window.start))
		window.updatedBefore = firstNonEmpty(dateEnd, formatSearchMoment(window.end))
	}

	if strings.Contains(lowered, "up to now") || strings.Contains(lowered, "through now") || strings.Contains(lowered, "until now") || strings.Contains(lowered, "last ") {
		window.createdBefore = ""
		window.updatedBefore = ""
	}
	return window
}

func inferActivity(lowered string) string {
	switch {
	case strings.Contains(lowered, "new or updated"), strings.Contains(lowered, "created or updated"):
		return "either"
	case strings.Contains(lowered, "new repo"), strings.Contains(lowered, "new repos"), strings.Contains(lowered, "created repo"), strings.Contains(lowered, "created repos"):
		return "created"
	default:
		return "updated"
	}
}

func inferQuery(lowered string) string {
	switch {
	case strings.Contains(lowered, "0 stars"), strings.Contains(lowered, "zero stars"):
		return "stars:>=0"
	case strings.Contains(lowered, "all stars"):
		return "stars:>=0"
	case strings.Contains(lowered, "high signal"):
		return "stars:>20"
	default:
		return "stars:>5"
	}
}

func wantsPersistence(lowered string) bool {
	return strings.Contains(lowered, "checkpoint") || strings.Contains(lowered, "resume") || strings.Contains(lowered, "save state") || strings.Contains(lowered, "persist")
}

func wantsFailOnFindings(lowered string) bool {
	return strings.Contains(lowered, "fail on findings") || strings.Contains(lowered, "exit non-zero") || strings.Contains(lowered, "non-zero") || strings.Contains(lowered, "gate") || strings.Contains(lowered, "ci")
}

func wantsSummary(lowered string) bool {
	return strings.Contains(lowered, "summary") || strings.Contains(lowered, "compact") || strings.Contains(lowered, "verdict")
}

func extractUserTargets(prompt string) []string {
	matches := userPattern.FindAllStringSubmatch(prompt, -1)
	usernames := make([]string, 0, len(matches))
	for _, match := range matches {
		if len(match) == 2 {
			usernames = append(usernames, match[1])
		}
	}
	return usernames
}

func uniqueStrings(values []string) []string {
	seen := make(map[string]struct{}, len(values))
	out := make([]string, 0, len(values))
	for _, value := range values {
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		out = append(out, value)
	}
	return out
}

func buildInvocation(argv ...string) recommendedInvocation {
	return recommendedInvocation{
		Argv:         argv,
		ShellCommand: strings.Join(argv, " "),
	}
}

func buildBatchInvocation(argv []string, stdinLines []string) recommendedInvocation {
	quoted := make([]string, 0, len(stdinLines))
	for _, line := range stdinLines {
		quoted = append(quoted, line)
	}
	return recommendedInvocation{
		Argv:         argv,
		ShellCommand: fmt.Sprintf("printf '%s\\n' | %s", strings.Join(quoted, "\\n"), strings.Join(argv, " ")),
	}
}

func windowFlags(window resolvedTaskWindow) []string {
	flags := make([]string, 0, 8)
	if window.createdSince != "" {
		flags = append(flags, "--created-since", window.createdSince)
	}
	if window.createdBefore != "" {
		flags = append(flags, "--created-before", window.createdBefore)
	}
	if window.updatedSince != "" {
		flags = append(flags, "--since", window.updatedSince)
	}
	if window.updatedBefore != "" {
		flags = append(flags, "--updated-before", window.updatedBefore)
	}
	return flags
}

func mustParseLocalDate(value string, loc *time.Location) time.Time {
	parsed, err := time.ParseInLocation(time.DateOnly, value, loc)
	if err != nil {
		return time.Time{}
	}
	return parsed
}

func startOfDay(value time.Time) time.Time {
	year, month, day := value.Date()
	return time.Date(year, month, day, 0, 0, 0, 0, value.Location())
}

func endOfDay(value time.Time) time.Time {
	return startOfDay(value).Add(24*time.Hour - time.Second)
}

func isWholeDayBoundary(value time.Time) bool {
	return value.Hour() == 0 && value.Minute() == 0 && value.Second() == 0 && value.Nanosecond() == 0
}

func formatSearchMoment(value time.Time) string {
	if value.IsZero() {
		return ""
	}
	return value.UTC().Format(time.RFC3339)
}

func writeRecommendationText(w io.Writer, rec recommendation) error {
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("Command: %s\n", rec.Command))
	if rec.Subcommand != "" {
		sb.WriteString(fmt.Sprintf("Subcommand: %s\n", rec.Subcommand))
	}
	sb.WriteString(fmt.Sprintf("Confidence: %s\n", rec.Confidence))
	sb.WriteString(fmt.Sprintf("Follow-up needed: %t\n", rec.FollowUpNeeded))
	if rec.ParsedIntent.Activity != "" {
		sb.WriteString(fmt.Sprintf("Activity: %s\n", rec.ParsedIntent.Activity))
	}
	if rec.ResolvedTimeWindow != nil {
		if rec.ResolvedTimeWindow.Start != "" {
			sb.WriteString(fmt.Sprintf("Start: %s\n", rec.ResolvedTimeWindow.Start))
		}
		if rec.ResolvedTimeWindow.End != "" {
			sb.WriteString(fmt.Sprintf("End: %s\n", rec.ResolvedTimeWindow.End))
		}
	}
	for _, warning := range rec.Warnings {
		sb.WriteString(fmt.Sprintf("Warning: %s\n", warning))
	}
	for _, assumption := range rec.Assumptions {
		sb.WriteString(fmt.Sprintf("Assumption: %s\n", assumption))
	}
	for _, invocation := range rec.Invocations {
		sb.WriteString(fmt.Sprintf("Invoke: %s\n", invocation.ShellCommand))
	}
	_, err := io.WriteString(w, sb.String())
	return err
}
