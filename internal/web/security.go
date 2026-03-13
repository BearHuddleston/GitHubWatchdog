package web

import (
	"net"
	"net/http"
	"net/url"
	"strings"
)

func (s *Server) localWriteOnly(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !isLoopbackRequest(r) {
			http.Error(w, "Forbidden", http.StatusForbidden)
			return
		}
		if !isTrustedBrowserRequest(r) {
			http.Error(w, "Forbidden", http.StatusForbidden)
			return
		}
		next(w, r)
	}
}

func isLoopbackRequest(r *http.Request) bool {
	host := r.RemoteAddr
	if parsedHost, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
		host = parsedHost
	}
	host = strings.Trim(host, "[]")

	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func isTrustedBrowserRequest(r *http.Request) bool {
	targetHost := normalizedHost(r.Host)
	if targetHost == "" {
		return true
	}

	for _, header := range []string{"Origin", "Referer"} {
		value := strings.TrimSpace(r.Header.Get(header))
		if value == "" {
			continue
		}

		u, err := url.Parse(value)
		if err != nil || normalizedHost(u.Host) != targetHost {
			return false
		}
	}

	return true
}

func normalizedHost(hostport string) string {
	if hostport == "" {
		return ""
	}

	host := hostport
	if parsedHost, _, err := net.SplitHostPort(hostport); err == nil {
		host = parsedHost
	}

	return strings.Trim(strings.ToLower(host), "[]")
}
