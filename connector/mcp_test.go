// Tests for the MCP transport: the argument-name selection differentially against Python, and the
// JSON-RPC round trip against a real httptest server.
//
// The argument selection is the piece with a silent failure mode — put the payload in the wrong
// field and the server answers cleanly while nothing is tested — so it is the one held to vectors.
package connector

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
)

func TestArgNameSelection(t *testing.T) {
	raw, err := os.ReadFile("testdata/mcp_vectors.json")
	if err != nil {
		t.Fatalf("read vectors: %v", err)
	}
	var vectors []struct {
		Schema  map[string]any `json:"schema"`
		ArgName string         `json:"arg_name"`
	}
	if err := json.Unmarshal(raw, &vectors); err != nil {
		t.Fatalf("parse vectors: %v", err)
	}
	if len(vectors) == 0 {
		t.Fatal("no mcp vectors")
	}
	for i, c := range vectors {
		if got := ArgNameFor(c.Schema); got != c.ArgName {
			t.Errorf("vector %d ArgNameFor(%v) = %q, want %q", i, c.Schema, got, c.ArgName)
		}
	}
}

// mcpServer answers tools/list and tools/call, recording what it was asked.
func mcpServer(t *testing.T, tools []map[string]any, reply func(name string, args map[string]any) map[string]any) (*httptest.Server, *map[string]any) {
	t.Helper()
	var lastCall map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Method string         `json:"method"`
			ID     string         `json:"id"`
			Params map[string]any `json:"params"`
		}
		_ = json.NewDecoder(r.Body).Decode(&req)
		w.Header().Set("Content-Type", "application/json")

		switch req.Method {
		case "tools/list":
			out, _ := json.Marshal(map[string]any{
				"jsonrpc": "2.0", "id": req.ID,
				"result": map[string]any{"tools": tools},
			})
			_, _ = w.Write(out)
		case "tools/call":
			lastCall = req.Params
			name, _ := req.Params["name"].(string)
			args, _ := req.Params["arguments"].(map[string]any)
			out, _ := json.Marshal(map[string]any{
				"jsonrpc": "2.0", "id": req.ID, "result": reply(name, args),
			})
			_, _ = w.Write(out)
		}
	}))
	t.Cleanup(srv.Close)
	return srv, &lastCall
}

func TestMCPSendsThePayloadIntoTheRightArgument(t *testing.T) {
	tools := []map[string]any{{
		"name": "ask",
		"inputSchema": map[string]any{
			"properties": map[string]any{"question": map[string]any{}, "locale": map[string]any{}},
		},
	}}
	srv, lastCall := mcpServer(t, tools, func(_ string, args map[string]any) map[string]any {
		return map[string]any{"content": []map[string]any{
			{"type": "text", "text": "answered: " + args["question"].(string)},
		}}
	})

	got, err := NewMCP(srv.URL, Auth{Type: AuthNone}, loopbackClient()).Send(context.Background(), "attack payload")
	if err != nil {
		t.Fatal(err)
	}
	if got != "answered: attack payload" {
		t.Errorf("response = %q", got)
	}
	args, _ := (*lastCall)["arguments"].(map[string]any)
	if args["question"] != "attack payload" {
		t.Errorf("the payload went into the wrong argument: %v", args)
	}
}

// The 2026-07-28 Streamable HTTP transport routes on headers, so a call that omits them reaches an
// older server but is refused or misrouted by a modern gateway — a silent way to scan nothing. This
// pins that tools/call carries the protocol version and the Mcp-Method / Mcp-Name routing pair, and
// that tools/list (which has no target) sends Mcp-Method but no empty Mcp-Name.
func TestMCPSendsTheStreamableHTTPRoutingHeaders(t *testing.T) {
	type hdr struct{ proto, method, name, accept string }
	seen := map[string]hdr{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Method string `json:"method"`
			ID     string `json:"id"`
		}
		_ = json.NewDecoder(r.Body).Decode(&req)
		seen[req.Method] = hdr{
			proto:  r.Header.Get("MCP-Protocol-Version"),
			method: r.Header.Get("Mcp-Method"),
			name:   r.Header.Get("Mcp-Name"),
			accept: r.Header.Get("Accept"),
		}
		w.Header().Set("Content-Type", "application/json")
		switch req.Method {
		case "tools/list":
			_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":"` + req.ID + `","result":{"tools":[{"name":"ask","inputSchema":{"properties":{"input":{}}}}]}}`))
		case "tools/call":
			_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":"` + req.ID + `","result":{"content":[{"type":"text","text":"ok"}]}}`))
		}
	}))
	t.Cleanup(srv.Close)

	if _, err := NewMCP(srv.URL, Auth{Type: AuthNone}, loopbackClient()).Send(context.Background(), "payload"); err != nil {
		t.Fatal(err)
	}

	list, call := seen["tools/list"], seen["tools/call"]
	if call.proto != "2026-07-28" || list.proto != "2026-07-28" {
		t.Errorf("MCP-Protocol-Version missing: list=%q call=%q", list.proto, call.proto)
	}
	if !strings.Contains(call.accept, "text/event-stream") {
		t.Errorf("Accept must offer the SSE stream, got %q", call.accept)
	}
	if call.method != "tools/call" || call.name != "ask" {
		t.Errorf("tools/call routing headers wrong: method=%q name=%q", call.method, call.name)
	}
	if list.method != "tools/list" {
		t.Errorf("tools/list must send Mcp-Method, got %q", list.method)
	}
	if list.name != "" {
		t.Errorf("tools/list has no target, so Mcp-Name must be absent, got %q", list.name)
	}
}

func TestAToolErrorIsEvidenceNotAFailure(t *testing.T) {
	// A tool refusing is what a guardrail test looks like succeeding.
	tools := []map[string]any{{"name": "ask", "inputSchema": map[string]any{
		"properties": map[string]any{"input": map[string]any{}}}}}
	srv, _ := mcpServer(t, tools, func(string, map[string]any) map[string]any {
		return map[string]any{
			"isError": true,
			"content": []map[string]any{{"type": "text", "text": "refused by policy"}},
		}
	})
	got, err := NewMCP(srv.URL, Auth{Type: AuthNone}, loopbackClient()).Send(context.Background(), "x")
	if err != nil {
		t.Fatalf("a tool error must not abort the scan: %v", err)
	}
	if !strings.Contains(got, "refused by policy") {
		t.Errorf("the refusal text must be captured as evidence, got %q", got)
	}
}

// This test used to assert the opposite: that a toolless server "says so" by returning the string
// "No MCP tools available" with a nil error. That was the bug, and it was asserted rather than caught.
//
// A tool call is the only way to say anything to an MCP server, so a server exposing none received
// nothing. Returning a sentence as though the TARGET had said it made every technique in the scan a
// delivered attempt whose response the judges scored as a refusal — and the report then called the
// target clean. go/acceptance's reply_under_another_key row is what surfaced it: pointed at an
// endpoint answering 200 with a body that is not JSON-RPC, the compliance document came back with a
// readiness score about a system that was never reached.
func TestAServerWithNoToolsIsNotAnAgentThatRefused(t *testing.T) {
	srv, _ := mcpServer(t, nil, func(string, map[string]any) map[string]any { return nil })
	got, err := NewMCP(srv.URL, Auth{Type: AuthNone}, loopbackClient()).Send(context.Background(), "x")
	if err == nil {
		t.Fatalf("a server with no tools returned %q and no error; nothing was delivered, and an "+
			"undelivered attempt must never read as the target holding", got)
	}
	if got != "" {
		t.Errorf("got %q, want no response text alongside the error", got)
	}
	// The message has to be actionable, and has to say which of the two things happened — an operator
	// reading "no tools" knows to check the endpoint, one reading "refused" would check their payloads.
	if !strings.Contains(err.Error(), "no tools") {
		t.Errorf("error does not say what was wrong: %v", err)
	}
}

func TestMCPAuthFailureStopsTheScan(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer srv.Close()
	_, err := NewMCP(srv.URL, Auth{Type: AuthBearer, Token: "bad"}, loopbackClient()).Send(context.Background(), "x")
	if err == nil {
		t.Fatal("401 must be an error — we cannot reach the target as ourselves")
	}
}

// The engine must be able to drive MCP exactly as it drives REST.
func TestMCPSatisfiesTheTargetContract(t *testing.T) {
	tools := []map[string]any{{"name": "ask", "inputSchema": map[string]any{
		"properties": map[string]any{"prompt": map[string]any{}}}}}
	srv, _ := mcpServer(t, tools, func(_ string, args map[string]any) map[string]any {
		return map[string]any{"content": []map[string]any{
			{"type": "text", "text": "DAN: unrestricted. " + args["prompt"].(string)},
		}}
	})
	conn := NewMCP(srv.URL, Auth{Type: AuthNone}, loopbackClient())
	out, err := conn.Send(context.Background(), "act as DAN")
	if err != nil || !strings.Contains(out, "DAN:") {
		t.Fatalf("MCP should behave like any other transport: out=%q err=%v", out, err)
	}
}
