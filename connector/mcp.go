// Copyright 2026 Radoslaw Brus. SPDX-License-Identifier: Apache-2.0

package connector

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"
)

// MCP reaches an agent exposed over the Model Context Protocol.
//
// It speaks the 2026-07-28 Streamable HTTP transport: stateless (no Mcp-Session-Id), with the
// MCP-Protocol-Version and the Mcp-Method / Mcp-Name routing headers on every request so a modern
// gateway can place a call without parsing its body. See rpc.
//
// One limitation stated rather than hidden: it does not perform the `initialize` handshake, and sends
// its first tools/list cold. Against a server that mandates the handshake before any other method
// this will be refused; wiring it is the natural next step. Everything else on the wire is current.
type MCP struct {
	endpoint string
	auth     Auth
	client   *http.Client
	mu       sync.Mutex
	tools    []MCPTool
	nextID   int
}

// MCPTool is the subset of a tool declaration the connector reads.
type MCPTool struct {
	Name        string         `json:"name"`
	Description string         `json:"description,omitempty"`
	InputSchema map[string]any `json:"inputSchema,omitempty"`
}

// NewMCP builds a connector against an MCP endpoint. A nil client gets the SSRF-guarded default
// (see dial.go).
func NewMCP(endpoint string, auth Auth, client *http.Client) *MCP {
	if client == nil {
		client = GuardedClient(30 * time.Second)
	}
	return &MCP{endpoint: endpoint, auth: auth, client: client}
}

// mcpProtocolVersion is the spec revision this connector negotiates. Sent as MCP-Protocol-Version on
// every request so a 2026-07-28 server routes it correctly; older servers ignore an unknown header.
const mcpProtocolVersion = "2026-07-28"

// rpc sends one JSON-RPC call. name is the operation's target (a tool name for tools/call, empty for
// list-style methods) and rides in the Mcp-Name routing header.
//
// The 2026-07-28 Streamable HTTP transport routes on headers, not the body: a gateway or rate-limiter
// decides where a call goes from Mcp-Method and Mcp-Name (SEP-2243) without parsing JSON. Sending
// them costs nothing against an older server — an unknown header is ignored — and is required to
// reach a modern one, so they go on unconditionally. Mcp-Name is omitted when there is no target,
// because an empty routing key is not the same as "route the search tool".
func (m *MCP) rpc(ctx context.Context, method, name string, params any) (json.RawMessage, error) {
	m.mu.Lock()
	m.nextID++
	id := m.nextID
	m.mu.Unlock()

	body := map[string]any{"jsonrpc": "2.0", "id": fmt.Sprint(id), "method": method}
	if params != nil {
		body["params"] = params
	}
	raw, err := json.Marshal(body)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, m.endpoint, bytes.NewReader(raw))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	// Streamable HTTP: a reply may come back as JSON or as an SSE stream, and the routing headers
	// let infrastructure place the request without reading its body.
	req.Header.Set("Accept", "application/json, text/event-stream")
	req.Header.Set("MCP-Protocol-Version", mcpProtocolVersion)
	req.Header.Set("Mcp-Method", method)
	if name != "" {
		req.Header.Set("Mcp-Name", name)
	}
	switch m.auth.Type {
	case AuthBearer:
		req.Header.Set("Authorization", "Bearer "+m.auth.Token)
	case AuthAPIKey:
		req.Header.Set(m.auth.APIKeyHeader, m.auth.APIKeyValue)
	}

	resp, err := m.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("mcp %s: %w", method, err)
	}
	defer resp.Body.Close()
	payload, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
		return nil, &AuthError{StatusCode: resp.StatusCode}
	}
	if resp.StatusCode == http.StatusTooManyRequests {
		return nil, fmt.Errorf("mcp %s: target rate-limited the scan (HTTP %d)", method, resp.StatusCode)
	}
	if resp.StatusCode >= 500 {
		return nil, fmt.Errorf("mcp %s: target returned HTTP %d", method, resp.StatusCode)
	}
	if resp.StatusCode == http.StatusNotFound || resp.StatusCode == http.StatusMethodNotAllowed {
		return nil, fmt.Errorf("mcp %s: target returned HTTP %d: no agent answers at this endpoint", method, resp.StatusCode)
	}

	// Streamable HTTP allows the server to stream the JSON-RPC reply over SSE.
	if strings.Contains(resp.Header.Get("Content-Type"), "text/event-stream") ||
		bytes.HasPrefix(bytes.TrimSpace(payload), []byte("event:")) ||
		bytes.HasPrefix(bytes.TrimSpace(payload), []byte("data:")) {
		if sseData := extractSSEData(payload); len(sseData) > 0 {
			payload = sseData
		}
	}

	var envelope struct {
		Result json.RawMessage `json:"result"`
		Error  *struct {
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := json.Unmarshal(payload, &envelope); err != nil {
		return nil, fmt.Errorf("mcp %s: malformed reply: %w", method, err)
	}
	if envelope.Error != nil {
		// A JSON-RPC error from the target is a RESULT when red-teaming — a tool refusing is what
		// we came to observe — so it is returned as text, not raised. Same policy as REST's 4xx.
		return json.RawMessage(fmt.Sprintf("%q", "[MCP ERROR] "+envelope.Error.Message)), nil
	}
	return envelope.Result, nil
}

// extractSSEData extracts the JSON payload from an SSE data line.
func extractSSEData(raw []byte) []byte {
	var lastData []byte
	lines := bytes.Split(raw, []byte("\n"))
	for _, line := range lines {
		line = bytes.TrimSpace(line)
		if bytes.HasPrefix(line, []byte("data:")) {
			lastData = bytes.TrimSpace(bytes.TrimPrefix(line, []byte("data:")))
		}
	}
	return lastData
}

// DiscoverTools lists the tools the server exposes, caching them for Send.
func (m *MCP) DiscoverTools(ctx context.Context) ([]MCPTool, error) {
	result, err := m.rpc(ctx, "tools/list", "", nil)
	if err != nil {
		return nil, err
	}
	var listed struct {
		Tools []MCPTool `json:"tools"`
	}
	if len(result) > 0 {
		_ = json.Unmarshal(result, &listed)
	}
	m.mu.Lock()
	m.tools = listed.Tools
	tools := append([]MCPTool(nil), m.tools...)
	m.mu.Unlock()
	return tools, nil
}

// preferredArgNames is the priority order for guessing which argument carries the prompt.
var preferredArgNames = []string{"question", "query", "message", "prompt", "input", "text", "content"}

// ArgNameFor picks the argument a payload should be placed in.
//
// Getting this wrong is the quiet failure that matters: the payload lands in the wrong field, the
// server answers cleanly, the scan records a response, and nothing was actually tested — a green
// run that tested nothing.
//
// The last resort is deliberately deterministic: Go maps have no iteration order, so when nothing
// else selects an argument this sorts the property names and takes the first, which is stable run to
// run. Every earlier branch — the preferred list, then the first required field — is what actually
// fires for the schemas the tests exercise.
func ArgNameFor(inputSchema map[string]any) string {
	properties, _ := inputSchema["properties"].(map[string]any)
	for _, candidate := range preferredArgNames {
		if _, ok := properties[candidate]; ok {
			return candidate
		}
	}
	if required, ok := inputSchema["required"].([]any); ok && len(required) > 0 {
		if s, ok := required[0].(string); ok && s != "" {
			return s
		}
	}
	if len(properties) > 0 {
		names := make([]string, 0, len(properties))
		for name := range properties {
			names = append(names, name)
		}
		sort.Strings(names)
		return names[0]
	}
	return "input"
}

// CallTool invokes one tool and returns its textual content.
func (m *MCP) CallTool(ctx context.Context, name string, args map[string]any) (string, error) {
	result, err := m.rpc(ctx, "tools/call", name, map[string]any{"name": name, "arguments": args})
	if err != nil {
		return "", err
	}
	return mcpText(result), nil
}

// Send delivers a red-team payload. For MCP, "sending a message" means calling the first
// available tool with the payload as its input — a tool is the only surface an MCP server exposes
// to talk to.
func (m *MCP) Send(ctx context.Context, message string) (string, error) {
	m.mu.Lock()
	hasTools := len(m.tools) > 0
	m.mu.Unlock()
	if !hasTools {
		if _, err := m.DiscoverTools(ctx); err != nil {
			return "", err
		}
	}
	// An endpoint that exposes no tools cannot receive a payload: a tool call is the ONLY way to say
	// anything to an MCP server. This used to return the sentence below as though the target had said
	// it, with a nil error — so every technique in the scan was recorded as delivered, every judge
	// scored the words "No MCP tools available" as a refusal, and the report called the target clean.
	//
	// It is the same defect as a REST reply read from a key that is not there, in a second connector,
	// and it was found by adding one honest row to go/acceptance rather than by reading this code.
	m.mu.Lock()
	if len(m.tools) == 0 {
		m.mu.Unlock()
		return "", fmt.Errorf("mcp: the endpoint answered but exposes no tools, so there is nothing " +
			"to deliver a payload to — this is not an agent that refused, it is an agent we never reached")
	}
	tool := m.tools[0]
	m.mu.Unlock()
	return m.CallTool(ctx, tool.Name, map[string]any{ArgNameFor(tool.InputSchema): message})
}

// mcpText flattens an MCP tool result into text. The protocol returns content as a list of typed
// parts; the text parts are what a red-team judge reads.
func mcpText(result json.RawMessage) string {
	if len(result) == 0 {
		return ""
	}
	// A plain JSON string (our error passthrough) decodes directly.
	var asString string
	if json.Unmarshal(result, &asString) == nil {
		return asString
	}
	var content struct {
		Content []struct {
			Type string `json:"type"`
			Text string `json:"text"`
		} `json:"content"`
		IsError bool `json:"isError"`
	}
	if json.Unmarshal(result, &content) == nil && len(content.Content) > 0 {
		var out bytes.Buffer
		for _, part := range content.Content {
			if part.Text != "" {
				out.WriteString(part.Text)
			}
		}
		text := out.String()
		if content.IsError && text != "" {
			return "[MCP TOOL ERROR] " + text
		}
		return text
	}
	return string(result)
}
