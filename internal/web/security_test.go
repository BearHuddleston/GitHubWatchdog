package web

import (
	"net/http/httptest"
	"testing"
)

func TestIsLoopbackRequest(t *testing.T) {
	req := httptest.NewRequest("POST", "http://127.0.0.1:8080/api/user/status", nil)
	req.RemoteAddr = "127.0.0.1:12345"

	if !isLoopbackRequest(req) {
		t.Fatal("expected loopback request to be allowed")
	}
}

func TestIsLoopbackRequestRejectsRemoteHost(t *testing.T) {
	req := httptest.NewRequest("POST", "http://127.0.0.1:8080/api/user/status", nil)
	req.RemoteAddr = "192.0.2.10:12345"

	if isLoopbackRequest(req) {
		t.Fatal("expected non-loopback request to be rejected")
	}
}

func TestIsTrustedBrowserRequest(t *testing.T) {
	req := httptest.NewRequest("POST", "http://127.0.0.1:8080/api/user/status", nil)
	req.Host = "127.0.0.1:8080"
	req.Header.Set("Origin", "http://127.0.0.1:8080")
	req.Header.Set("Referer", "http://127.0.0.1:8080/users")

	if !isTrustedBrowserRequest(req) {
		t.Fatal("expected same-origin browser request to be trusted")
	}
}

func TestIsTrustedBrowserRequestRejectsCrossSite(t *testing.T) {
	req := httptest.NewRequest("POST", "http://127.0.0.1:8080/api/user/status", nil)
	req.Host = "127.0.0.1:8080"
	req.Header.Set("Origin", "https://evil.example")

	if isTrustedBrowserRequest(req) {
		t.Fatal("expected cross-site browser request to be rejected")
	}
}
