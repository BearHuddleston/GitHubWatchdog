// Package ollama provides a client for interacting with the Ollama API
package ollama

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

// Client represents an Ollama API client
type Client struct {
	baseURL    string
	httpClient *http.Client
}

// GenerateRequest represents a request to the Ollama generate endpoint
type GenerateRequest struct {
	Model    string  `json:"model"`
	Prompt   string  `json:"prompt"`
	Context  []int   `json:"context,omitempty"`
	Options  Options `json:"options,omitempty"`
	System   string  `json:"system,omitempty"`
	Format   string  `json:"format,omitempty"`
	Template string  `json:"template,omitempty"`
	Stream   bool    `json:"stream,omitempty"`
}

// Options represents model generation options
type Options struct {
	NumKeep          int      `json:"num_keep,omitempty"`
	Seed             int      `json:"seed,omitempty"`
	NumPredict       int      `json:"num_predict,omitempty"`
	TopK             int      `json:"top_k,omitempty"`
	TopP             float64  `json:"top_p,omitempty"`
	MinP             float64  `json:"min_p,omitempty"`
	TypicalP         float64  `json:"typical_p,omitempty"`
	RepeatLastN      int      `json:"repeat_last_n,omitempty"`
	Temperature      float64  `json:"temperature,omitempty"`
	RepeatPenalty    float64  `json:"repeat_penalty,omitempty"`
	PresencePenalty  float64  `json:"presence_penalty,omitempty"`
	FrequencyPenalty float64  `json:"frequency_penalty,omitempty"`
	Mirostat         int      `json:"mirostat,omitempty"`
	MirostatTau      float64  `json:"mirostat_tau,omitempty"`
	MirostatEta      float64  `json:"mirostat_eta,omitempty"`
	PenalizeNewline  bool     `json:"penalize_newline,omitempty"`
	Stop             []string `json:"stop,omitempty"`
	Numa             bool     `json:"numa,omitempty"`
	NumCtx           int      `json:"num_ctx,omitempty"`
	NumBatch         int      `json:"num_batch,omitempty"`
	NumGpu           int      `json:"num_gpu,omitempty"`
	MainGpu          int      `json:"main_gpu,omitempty"`
	LowVram          bool     `json:"low_vram,omitempty"`
	VocabOnly        bool     `json:"vocab_only,omitempty"`
	UseMmap          bool     `json:"use_mmap,omitempty"`
	UseMlock         bool     `json:"use_mlock,omitempty"`
	NumThread        int      `json:"num_thread,omitempty"`
}

// GenerateResponse represents a response from the Ollama generate endpoint
type GenerateResponse struct {
	Model              string    `json:"model"`
	CreatedAt          time.Time `json:"created_at"`
	Response           string    `json:"response"`
	Context            []int     `json:"context,omitempty"`
	Done               bool      `json:"done"`
	TotalDuration      int64     `json:"total_duration,omitempty"`
	LoadDuration       int64     `json:"load_duration,omitempty"`
	PromptEvalDuration int64     `json:"prompt_eval_duration,omitempty"`
	EvalDuration       int64     `json:"eval_duration,omitempty"`
}

// DefaultSystemPrompt is the system prompt used for threat analysis
const DefaultSystemPrompt = `You are a cybersecurity threat analyst evaluating potential malicious GitHub repositories.
Analyze the provided repository information and provide a detailed assessment of the security risk. 
Consider code patterns, suspicious behaviors, obfuscation techniques, and other indicators of potentially malicious intent.
Be objective, thorough, and provide specific examples from the repository content where applicable.
Format your analysis in markdown with sections for Observations, Risk Analysis, and Recommendations.
Use bullets for key points and code blocks for examples.`

// NewClient creates a new Ollama client
func NewClient(baseURL string) *Client {
	return &Client{
		baseURL: baseURL,
		httpClient: &http.Client{
			Timeout: 5 * time.Minute, // Extended timeout for large requests
		},
	}
}

// Generate sends a request to the Ollama API to generate a response
func (c *Client) Generate(ctx context.Context, model, prompt string) (string, error) {
	// Ensure we have a valid model and non-empty prompt
	if model == "" {
		model = "llama3.2" // Fallback to default model
	}

	if prompt == "" {
		return "", fmt.Errorf("prompt cannot be empty")
	}

	// Add system prompt to request if needed
	system := DefaultSystemPrompt
	
	// For debug only
	_ = system

	// Create a minimal raw request body that matches the curl example exactly
	requestMap := map[string]interface{}{
		"model": model,
		"prompt": prompt,
		"stream": false,
		"options": map[string]interface{}{
			"num_predict": 4096,
			"temperature": 0.8,
			"top_k": 20,
			"top_p": 0.9,
			"seed": 42,
		},
	}

	// For testing/debugging
	debugReq, _ := json.MarshalIndent(requestMap, "", "  ")
	fmt.Printf("Sending request to Ollama: %s\n", debugReq)

	reqBody, err := json.Marshal(requestMap)
	if err != nil {
		return "", fmt.Errorf("marshaling request: %w", err)
	}

	httpReq, err := http.NewRequestWithContext(
		ctx,
		"POST",
		fmt.Sprintf("%s/api/generate", c.baseURL),
		bytes.NewReader(reqBody),
	)
	if err != nil {
		return "", fmt.Errorf("creating request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(httpReq)
	if err != nil {
		return "", fmt.Errorf("sending request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		bodyBytes, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("unexpected status code: %d, body: %s", resp.StatusCode, string(bodyBytes))
	}

	// Parse response manually to capture exactly what we need
	responseBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("reading response body: %w", err)
	}

	// Log the raw response for debugging
	fmt.Printf("Raw response from Ollama: %s\n", string(responseBody))

	// Parse into generic map to avoid struct validation issues
	var responseMap map[string]interface{}
	if err := json.Unmarshal(responseBody, &responseMap); err != nil {
		return "", fmt.Errorf("parsing response JSON: %w", err)
	}

	// Extract the response field directly
	responseText, ok := responseMap["response"].(string)
	if !ok || responseText == "" {
		return "", fmt.Errorf("invalid or missing response field in Ollama result")
	}

	// Validate the response - if too short, provide a fallback
	if len(responseText) < 50 || responseText == "*" || responseText == "**" || responseText == "#" {
		return fmt.Sprintf(`# Security Analysis

## Observations
* Unable to generate a proper analysis
* Limited context or model issue detected

## Risk Assessment
* Cannot provide risk assessment with current response

## Recommendations
* Try again with more context
* Ensure Ollama is properly set up with llama3.2 model
* Current response was: "%s"
`, responseText), nil
	}

	return responseText, nil
}
