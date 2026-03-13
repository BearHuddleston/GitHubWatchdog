package ollama

import "testing"

func TestBuildGenerateRequestUsesDefaultsAndSystemPrompt(t *testing.T) {
	req := buildGenerateRequest("", "analyze this repository")

	if req.Model != "llama3.2" {
		t.Fatalf("expected default model, got %q", req.Model)
	}
	if req.System != DefaultSystemPrompt {
		t.Fatal("expected default system prompt to be attached to Ollama requests")
	}
	if req.Options.NumPredict != 4096 {
		t.Fatalf("expected NumPredict=4096, got %d", req.Options.NumPredict)
	}
	if req.Stream {
		t.Fatal("expected stream=false by default")
	}
}
