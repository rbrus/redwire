// Copyright 2026 Radoslaw Brus. SPDX-License-Identifier: Apache-2.0

package connector

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/rbrus/redwire/pyjson"
)

// A2A reaches an agent that speaks Agent-to-Agent: task-based message exchange over JSON-RPC, with
// discovery via an Agent Card at /.well-known/agent-card.json (agent.json before spec 0.3; both are
// read at discovery).
//
// Like MCP it is JSON-RPC over HTTP, but the shape is different: a message is a `tasks/send` with a
// role and typed parts, and the reply nests the answer three ways. The extraction below reproduces
// that layering exactly, because a red-team judge reads whatever it returns and a wrong extraction
// changes what a scan records as the target's answer.
//
// The Agent Card is read for one thing only — the endpoint and the auth scheme it declares — and its
// free-text fields (description, skills) are never routed to a model. That is deliberate: a hostile
// server can plant instructions in those fields (the Agent Card injection class, A2A-2026-001), and
// a client that hands card text to its own LLM lets a target attack the scanner. Here the card is
// data, not instructions.
type A2A struct {
	endpoint string
	auth     Auth
	client   *http.Client
	mu       sync.Mutex
	taskID   string
	// dialect is pinned after the first successful send; serverTaskID is the 0.3 task the server
	// named, which keeps a multi-turn conversation one task.
	dialect      a2aDialect
	serverTaskID string
}

// NewA2A builds a connector. It generates a task id on first use, kept across sends so the whole
// conversation is one task — the A2A equivalent of a session. A nil client gets the SSRF-guarded
// default (see dial.go).
func NewA2A(endpoint string, auth Auth, client *http.Client) *A2A {
	if client == nil {
		client = GuardedClient(30 * time.Second)
	}
	return &A2A{endpoint: endpoint, auth: auth, client: client}
}

func (a *A2A) headers(req *http.Request) {
	req.Header.Set("Content-Type", "application/json")
	switch a.auth.Type {
	case AuthBearer:
		req.Header.Set("Authorization", "Bearer "+a.auth.Token)
	case AuthAPIKey:
		req.Header.Set(a.auth.APIKeyHeader, a.auth.APIKeyValue)
	}
}

// a2aDialect is which generation of the protocol a target speaks.
//
// A2A renamed the send verb at spec 0.3: tasks/send became message/send, and a part's discriminator
// moved from "type" to "kind". Both are in the wild — Google's agents-cli and Agent Runtime serve
// 0.3, while most deployed agents were copied from a 0.2.x sample. Sending one and giving up meant
// the scanner could not reach half the ecosystem, and against the modern half it could not reach a
// target at all: every payload came back JSON-RPC -32601 before a technique landed.
type a2aDialect int

const (
	a2aAuto a2aDialect = iota // try the current spec, fall back once
	a2aV03                    // message/send, parts keyed "kind"
	a2aV02                    // tasks/send, parts keyed "type"
)

// rpcMethodNotFound is the one JSON-RPC code that means "wrong dialect" rather than "bad request".
const rpcMethodNotFound = -32601

// Send delivers one payload as an A2A message and returns the agent's answer.
//
// The dialect is negotiated once per connector and then pinned: the first send tries the current
// spec, and only a -32601 — the server saying it does not know that method — earns a retry on the
// older one. Any other failure is the target's answer and is returned as it always was.
func (a *A2A) Send(ctx context.Context, message string) (string, error) {
	a.mu.Lock()
	if a.taskID == "" {
		a.taskID = uuid.NewString()
	}
	dialect := a.dialect
	a.mu.Unlock()

	if dialect == a2aAuto {
		dialect = a2aV03
	}
	result, code, err := a.send(ctx, dialect, message)
	if err == nil {
		a.mu.Lock()
		a.dialect = dialect
		a.mu.Unlock()
		return result, nil
	}
	a.mu.Lock()
	curDialect := a.dialect
	a.mu.Unlock()
	// Only an unnegotiated connector retries, and only on the one code that means the verb was wrong.
	if curDialect == a2aAuto && dialect == a2aV03 && code == rpcMethodNotFound {
		result, _, retryErr := a.send(ctx, a2aV02, message)
		if retryErr == nil {
			a.mu.Lock()
			a.dialect = a2aV02
			a.mu.Unlock()
			return result, nil
		}
		return "", retryErr
	}
	return "", err
}

// send performs one exchange in one dialect. The returned int is the JSON-RPC error code when the
// target answered with an error object, and 0 otherwise.
func (a *A2A) send(ctx context.Context, dialect a2aDialect, message string) (string, int, error) {
	raw, err := json.Marshal(a.body(dialect, message))
	if err != nil {
		return "", 0, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, a.endpoint, bytes.NewReader(raw))
	if err != nil {
		return "", 0, err
	}
	a.headers(req)

	resp, err := a.client.Do(req)
	if err != nil {
		return "", 0, fmt.Errorf("a2a send: %w", err)
	}
	defer resp.Body.Close()
	payload, err := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if err != nil {
		return "", 0, err
	}
	if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
		return "", 0, &AuthError{StatusCode: resp.StatusCode}
	}
	// A throttle or a gateway failure is infrastructure, not the agent answering. Without this the
	// 429 body parsed as JSON, yielded nothing, and the empty string became the agent's reply — so a
	// rate-limited scan reported every obligation assessed against a target it never spoke to.
	if resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode >= 500 {
		return "", 0, fmt.Errorf("a2a: target returned HTTP %d", resp.StatusCode)
	}
	if resp.StatusCode == http.StatusNotFound || resp.StatusCode == http.StatusMethodNotAllowed {
		return "", 0, fmt.Errorf("a2a: target returned HTTP %d: no agent answers %s at this endpoint — %s",
			resp.StatusCode, req.Method, truncate(string(payload), 300))
	}

	var envelope struct {
		Result json.RawMessage `json:"result"`
		Error  *struct {
			Code    int    `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := json.Unmarshal(payload, &envelope); err != nil {
		return "", 0, fmt.Errorf("a2a: malformed reply: %w", err)
	}
	// No `result` at all is not an agent that answered with nothing — it is a body that is not an A2A
	// reply. It used to fall through to extractA2AFromRaw, which returns the literal "{}" for an empty
	// result, and that string became the agent's own words for every technique in the scan.
	//
	// ABSENT, not empty: a present `result` that happens to be `{}` is a real (if useless) reply and
	// still goes through the layering below, exactly as before.
	if len(envelope.Result) == 0 {
		code := 0
		if envelope.Error != nil {
			code = envelope.Error.Code
			return "", code, fmt.Errorf("a2a: target returned JSON-RPC error %d: %s",
				envelope.Error.Code, envelope.Error.Message)
		}
		return "", code, fmt.Errorf("a2a: target replied HTTP %d with no `result` in the envelope, so it did not "+
			"answer as an A2A agent — check the endpoint: %s", resp.StatusCode, truncate(string(payload), 300))
	}
	// 0.3 assigns the task id server-side, so it is read from the reply rather than minted here. It
	// is what keeps a multi-turn conversation one task, which is the whole point of the field.
	a.rememberTask(envelope.Result)
	return extractA2AFromRaw(envelope.Result), 0, nil
}

// body builds the request for one dialect.
func (a *A2A) body(dialect a2aDialect, message string) map[string]any {
	a.mu.Lock()
	taskID := a.taskID
	serverTaskID := a.serverTaskID
	a.mu.Unlock()

	if dialect == a2aV02 {
		// Byte-for-byte what this connector has always sent, so nothing about a 0.2 target changes.
		return map[string]any{
			"jsonrpc": "2.0",
			"id":      uuid.NewString(),
			"method":  "tasks/send",
			"params": map[string]any{
				"id": taskID,
				"message": map[string]any{
					"role":  "user",
					"parts": []map[string]any{{"type": "text", "text": message}},
				},
			},
		}
	}
	msg := map[string]any{
		"role":      "user",
		"messageId": uuid.NewString(),
		"parts":     []map[string]any{{"kind": "text", "text": message}},
	}
	// Only after the server has named the task: a client-minted id is 0.2 semantics and a 0.3 server
	// answers "task not found" to one it never issued.
	if serverTaskID != "" {
		msg["taskId"] = serverTaskID
	}
	return map[string]any{
		"jsonrpc": "2.0",
		"id":      uuid.NewString(),
		"method":  "message/send",
		"params":  map[string]any{"message": msg},
	}
}

// rememberTask captures the server's task id from a reply, so the next turn continues it.
func (a *A2A) rememberTask(rawResult json.RawMessage) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.serverTaskID != "" {
		return
	}
	var result struct {
		ID   string `json:"id"`
		Kind string `json:"kind"`
	}
	if json.Unmarshal(rawResult, &result) != nil {
		return
	}
	// A Task carries the id worth keeping. A bare Message reply has an id too, and continuing from
	// it would address the wrong thing.
	if result.Kind == "task" && result.ID != "" {
		a.serverTaskID = result.ID
	}
}

// extractA2AFromRaw pulls the answer out of an A2A result in the order the spec layers it: an
// artifact's text parts, then a status message's text parts, then the result JSON itself. Taking the
// RAW bytes for the last branch is load-bearing: the wire prints object keys in INSERTION order,
// while a Go map both iterates and marshals in SORTED order — so the fallback re-spaces the bytes as
// they arrived rather than marshalling a map, keeping the recorded evidence byte-for-byte what the
// target sent.
func extractA2AFromRaw(rawResult json.RawMessage) string {
	if len(rawResult) == 0 {
		return "{}"
	}
	var result map[string]any
	if json.Unmarshal(rawResult, &result) != nil || result == nil {
		return pyJSONFromRaw(rawResult)
	}

	if artifacts, ok := result["artifacts"].([]any); ok && len(artifacts) > 0 {
		if first, ok := artifacts[0].(map[string]any); ok {
			return joinTextParts(first["parts"])
		}
	}
	if status, ok := result["status"].(map[string]any); ok {
		if msg, ok := status["message"].(map[string]any); ok && msg != nil {
			return joinTextParts(msg["parts"])
		}
	}
	// Neither layer present: the result JSON itself, in its original key order.
	return pyJSONFromRaw(rawResult)
}

// pyJSONFromRaw re-encodes the raw result with Python-style json.dumps spacing (", " / ": ") in the
// object's original wire key order, which is what many agent backends emit and what the recorded
// evidence must preserve. The rule lives in package pyjson so there is exactly one copy of it; a
// second copy of a byte-exactness rule drifts silently.
func pyJSONFromRaw(rawResult json.RawMessage) string {
	return pyjson.FromRaw(rawResult)
}

// joinTextParts collects the text of every "text"-typed part, space-joined.
func joinTextParts(parts any) string {
	list, ok := parts.([]any)
	if !ok {
		return ""
	}
	var texts []string
	for _, p := range list {
		part, ok := p.(map[string]any)
		if !ok {
			continue
		}
		// 0.3 keys the discriminator "kind"; 0.2.x used "type". A reply may use either.
		kind, _ := part["kind"].(string)
		if kind == "" {
			kind, _ = part["type"].(string)
		}
		if kind == "text" {
			text, _ := part["text"].(string)
			texts = append(texts, text)
		}
	}
	return strings.Join(texts, " ")
}
