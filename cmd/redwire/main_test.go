// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestCLIVersion(t *testing.T) {
	var out, errOut bytes.Buffer
	if err := run([]string{"version"}, strings.NewReader(""), &out, &errOut); err != nil {
		t.Fatalf("run(version): %v", err)
	}
	if !strings.Contains(out.String(), "redwire") {
		t.Errorf("expected 'redwire' in version output, got: %q", out.String())
	}
}

func TestCLITransports(t *testing.T) {
	var out, errOut bytes.Buffer
	if err := run([]string{"transports"}, strings.NewReader(""), &out, &errOut); err != nil {
		t.Fatalf("run(transports): %v", err)
	}
	for _, transport := range []string{"rest", "mcp", "a2a", "ws", "browser"} {
		if !strings.Contains(out.String(), transport) {
			t.Errorf("expected transport %q in output, got:\n%s", transport, out.String())
		}
	}
}

func TestCLISendREST(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"reply":"echoed from test"}`))
	}))
	defer srv.Close()

	var out, errOut bytes.Buffer
	args := []string{
		"send",
		"-transport", "rest",
		"-endpoint", srv.URL,
		"-allow-private",
		"-req-field", "message",
		"-resp-field", "reply",
		"-message", "hello CLI",
	}
	if err := run(args, strings.NewReader(""), &out, &errOut); err != nil {
		t.Fatalf("run(send): %v", err)
	}
	if !strings.Contains(out.String(), "echoed from test") {
		t.Errorf("got %q, want 'echoed from test'", out.String())
	}
}

func TestCLIValidationErrors(t *testing.T) {
	var out, errOut bytes.Buffer
	if err := run([]string{"send"}, strings.NewReader(""), &out, &errOut); err == nil {
		t.Fatal("expected error on missing flags")
	}

	if err := run([]string{"unknown-cmd"}, strings.NewReader(""), &out, &errOut); err == nil {
		t.Fatal("expected error on unknown command")
	}
}
