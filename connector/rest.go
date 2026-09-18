// Copyright 2026 Radoslaw Brus. SPDX-License-Identifier: Apache-2.0

// Package connector holds the five transports that reach an AI agent: REST, MCP, A2A, WebSocket, and
// a chat widget driven in a real browser. Each satisfies one Send interface, so an attack is written
// once and runs against all five.
//
// The status-code policy is the part most worth reading, because it is counter-intuitive and
// load-bearing: when red-teaming, a 4xx from the target is usually a RESULT, not a failure —
// a content filter firing is exactly what we came to observe. So only auth rejections (401/403)
// are errors; everything else is captured as text and scored. A connector that raised on 4xx
// would silently convert every successful guardrail test into an aborted scan.
package connector

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// AuthType is the authentication scheme a target uses.
type AuthType string

const (
	AuthNone   AuthType = "none"
	AuthBearer AuthType = "bearer"
	AuthAPIKey AuthType = "api_key"
)

// Auth describes how to authenticate to the target.
type Auth struct {
	Type         AuthType `json:"type"`
	Token        string   `json:"token,omitempty"`
	APIKeyHeader string   `json:"api_key_header,omitempty"`
	APIKeyValue  string   `json:"api_key_value,omitempty"`
}

// Mapping is a dotted path into the request or response body, e.g. "input.text" or
// "choices[0].message.content".
//
// StaticFields is meaningful on the request side only: the fields every request must carry
// besides the message, keyed by dotted path, with any JSON value. It is what lets a transport
// that speaks one shape address a target that needs more than a message — an Azure Foundry agent
// through the Responses API is `{"agent_reference": {"type": "agent_reference", "name": …},
// "input": …}`, and without the first key the endpoint answers as the bare model, which is a
// different system from the one being assessed.
type Mapping struct {
	MessageField string         `json:"message_field"`
	SessionField string         `json:"session_field,omitempty"`
	StaticFields map[string]any `json:"static_fields,omitempty"`
}

// Config is what the REST transport needs to reach and authenticate to a target.
type Config struct {
	Endpoint        string        `json:"endpoint"`
	Auth            Auth          `json:"auth"`
	RequestMapping  Mapping       `json:"request_mapping"`
	ResponseMapping Mapping       `json:"response_mapping"`
	Timeout         time.Duration `json:"-"`
}

// REST sends attack payloads to an HTTP target and returns what it said back.
type REST struct {
	cfg       Config
	client    *http.Client
	sessionID string
}

// NewREST builds a connector. A nil client gets the SSRF-guarded default (see dial.go) with the
// configured timeout; a caller scanning a deliberately private target passes PrivateTargetClient.
func NewREST(cfg Config, client *http.Client) *REST {
	if cfg.Timeout == 0 {
		cfg.Timeout = 30 * time.Second
	}
	if client == nil {
		client = GuardedClient(cfg.Timeout)
	}
	return &REST{cfg: cfg, client: client}
}

// SetSession records a session id to include in requests when the target expects one.
func (r *REST) SetSession(id string) { r.sessionID = id }

func (r *REST) authHeaders() map[string]string {
	switch r.cfg.Auth.Type {
	case AuthBearer:
		return map[string]string{"Authorization": "Bearer " + r.cfg.Auth.Token}
	case AuthAPIKey:
		return map[string]string{r.cfg.Auth.APIKeyHeader: r.cfg.Auth.APIKeyValue}
	}
	return map[string]string{}
}

// buildPayload writes the static fields first and the message last, so the technique's payload
// wins a collision and a static value can never shadow what the scan meant to send. The static
// values are copied in, because SetNested writes THROUGH a map it finds on the path: a message
// field under a static object would otherwise mutate the configuration, and concurrent sends
// would race on it.
func (r *REST) buildPayload(message string) map[string]any {
	payload := map[string]any{}
	for path, value := range r.cfg.RequestMapping.StaticFields {
		SetNested(payload, path, cloneJSON(value))
	}
	SetNested(payload, r.cfg.RequestMapping.MessageField, message)
	if r.cfg.RequestMapping.SessionField != "" && r.sessionID != "" {
		SetNested(payload, r.cfg.RequestMapping.SessionField, r.sessionID)
	}
	return payload
}

// cloneJSON deep-copies the containers a decoded JSON value is made of; scalars are immutable and
// are returned as they are.
func cloneJSON(v any) any {
	switch x := v.(type) {
	case map[string]any:
		out := make(map[string]any, len(x))
		for k, val := range x {
			out[k] = cloneJSON(val)
		}
		return out
	case []any:
		out := make([]any, len(x))
		for i, val := range x {
			out[i] = cloneJSON(val)
		}
		return out
	}
	return v
}

// AuthError is the one failure that stops a scan: we cannot reach the target as ourselves.
type AuthError struct{ StatusCode int }

func (e *AuthError) Error() string {
	return fmt.Sprintf("HTTP %d auth rejected", e.StatusCode)
}

// Send delivers one payload and returns the target's answer as text.
func (r *REST) Send(ctx context.Context, message string) (string, error) {
	body, err := json.Marshal(r.buildPayload(message))
	if err != nil {
		return "", fmt.Errorf("encode request: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, r.cfg.Endpoint, bytes.NewReader(body))
	if err != nil {
		return "", fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	for k, v := range r.authHeaders() {
		req.Header.Set(k, v)
	}

	resp, err := r.client.Do(req)
	if err != nil {
		return "", fmt.Errorf("send: %w", err)
	}
	defer resp.Body.Close()

	raw, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return "", fmt.Errorf("read response: %w", err)
	}

	if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
		return "", &AuthError{StatusCode: resp.StatusCode}
	}
	if resp.StatusCode >= 500 {
		text := truncate(string(raw), 1000)
		var errDoc struct {
			Error struct {
				Message string `json:"message"`
			} `json:"error"`
		}
		if json.Unmarshal(raw, &errDoc) == nil && errDoc.Error.Message != "" {
			text = errDoc.Error.Message
		}
		// An ERROR, not a response. This used to hand the caller "[TARGET ERROR 502] …" with a nil
		// error so that one bad reply would not abort a scan — and the loops do continue on an error,
		// so nothing is lost by saying so honestly. What the marker cost was everything downstream:
		// the attempt carried no engine.Attempt.Error, so it counted as a technique the target
		// executed, and a gateway error page whose body happened to contain "DAN mode enabled" was
		// scored as two CRITICAL findings and reported at 75/100 readiness.
		return "", fmt.Errorf("target returned HTTP %d: %s", resp.StatusCode, text)
	}
	if resp.StatusCode == http.StatusTooManyRequests {
		// A rate limit is not a guardrail refusing us, and calling it REJECTED made it read as one —
		// a scan that was throttled scored the throttle as evidence the target held. It is the target
		// declining to speak at all, which is closer to a transport failure than to an answer.
		// Also an error: being throttled is the target declining to speak, not the target holding.
		return "", fmt.Errorf("target rate-limited the scan (HTTP %d): %s",
			resp.StatusCode, truncate(string(raw), 1000))
	}
	// 404 and 405 are not an agent answering — they are "there is no agent at this path, or it does
	// not accept this method". An ERROR, for exactly the reason the 5xx branch above gives.
	//
	// Found by pointing a real deployment at https://example.com/chat, which answers 405 to a POST:
	// 114 attempts were recorded as DELIVERED, the judges scored the "Example Domain" HTML page, and
	// the report came back Critical with three findings including "Agent Session Hijacking" at 0.75
	// confidence. That is the founding defect of go/acceptance — an attempt the target refused
	// counted as evidence about the target — surviving in the one 4xx range nobody had revisited.
	//
	// The other 4xx stay a response on purpose. A 400 or a 422 is an agent that received the payload
	// and rejected its shape, which is a real answer and sometimes the interesting one; 401 and 403
	// are already AuthError above. The rule is not "4xx is an error", it is "a status that means
	// nothing is listening here is an error".
	if resp.StatusCode == http.StatusNotFound || resp.StatusCode == http.StatusMethodNotAllowed {
		return "", fmt.Errorf("target returned HTTP %d: no agent answers %s at this endpoint — %s",
			resp.StatusCode, req.Method, truncate(string(raw), 300))
	}
	if resp.StatusCode >= 400 {
		return fmt.Sprintf("[TARGET REJECTED %d] %s", resp.StatusCode, truncate(string(raw), 1000)), nil
	}

	var doc map[string]any
	if err := json.Unmarshal(raw, &doc); err != nil {
		// A body that is not JSON is only an answer when no field was named to read it from. If the
		// target was configured to reply in a JSON field and did not, it did not answer in the shape
		// it was declared to answer in — and the case that matters is not a plain-text agent but a
		// sign-in interstitial served 200 OK, where nothing in the status says anything is wrong.
		// Its HTML used to become the agent's own words for every technique in the scan.
		if r.cfg.ResponseMapping.MessageField != "" {
			return "", fmt.Errorf("target replied with a non-JSON body while %q was expected: %s",
				r.cfg.ResponseMapping.MessageField, truncate(string(raw), 300))
		}
		return string(raw), nil // no field named: the body itself is the answer
	}
	// No field named: the body itself is the answer, the same rule the non-JSON branch above applies.
	if r.cfg.ResponseMapping.MessageField == "" {
		return string(raw), nil
	}

	// A JSON body that does not CONTAIN the named field is the third shape of "the target did not
	// answer in the shape it was declared to answer in", and it was the one this function let through.
	// Returning "" here reads downstream as an agent that replied with nothing — a delivered attempt
	// with an empty response — so every judge scores silence, every technique is recorded as defended
	// and the report says the target held. Found against an agent replying `{"reply": ...}` while the
	// mapping said `response`: 35 attempts, 0 findings, "Overall risk: Low", and nothing anywhere
	// saying not one response had been read.
	//
	// ABSENT, not empty. `{"response": ""}` is an agent that answered with an empty string, which is a
	// real result and must still be judged — turning that into an error would be the same bug facing
	// the other way.
	text, found := lookupNested(doc, r.cfg.ResponseMapping.MessageField)
	if !found {
		return "", fmt.Errorf("target replied 200 with JSON that has no %q field, so its answer could "+
			"not be read — check the response mapping against the body: %s",
			r.cfg.ResponseMapping.MessageField, truncate(string(raw), 300))
	}
	return text, nil
}

func truncate(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}

// --- dotted-path mapping ----------------------------------------------------------------

// SetNested writes a value at a dotted path, creating intermediate maps.
func SetNested(d map[string]any, path string, value any) {
	keys := strings.Split(path, ".")
	cur := d
	for _, k := range keys[:len(keys)-1] {
		next, ok := cur[k].(map[string]any)
		if !ok {
			next = map[string]any{}
			cur[k] = next
		}
		cur = next
	}
	cur[keys[len(keys)-1]] = value
}

// A negative index counts from the end: `output[-1]` is the last item. It exists because the
// Responses API of a reasoning model (the gpt-5 family) puts a `reasoning` item before the
// `message`, so `output[0].content[0].text` reads the wrong item and every reply comes back as
// "the key never resolved". A plain `[N]` index cannot express "the last one" without knowing the
// length in advance, so the negative form earns its place.
var indexRe = regexp.MustCompile(`^(\w+)\[(-?\d+)\]$`)

// GetNested reads a dotted path, supporting [N] indexing, and stringifies the result, returning ""
// when the path does not resolve.
//
// The quirks are deliberate and pinned by the tests: a missing key yields "" and then stringifies,
// and reaching a non-container mid-path returns that value stringified rather than erroring. Those
// quirks decide what a scan records as the target's answer. Callers that must tell a missing path
// from an empty value use lookupNested.
func GetNested(d map[string]any, path string) string {
	text, _ := lookupNested(d, path)
	return text
}

// lookupNested is GetNested plus the one fact GetNested throws away: whether the path RESOLVED.
//
// That distinction is load-bearing exactly once, in Send, and it is the difference between "this agent
// answered with nothing" and "we were reading the wrong key and never saw its answer". The first is a
// result; the second is a broken configuration that used to render as a clean scan.
func lookupNested(d map[string]any, path string) (string, bool) {
	var current any = d
	for _, segment := range strings.Split(path, ".") {
		if m := indexRe.FindStringSubmatch(segment); m != nil {
			key, idxStr := m[1], m[2]
			idx, _ := strconv.Atoi(idxStr)
			if cm, ok := current.(map[string]any); ok {
				if v, exists := cm[key]; exists {
					current = v
				} else {
					return "", false
				}
			}
			cl, ok := current.([]any)
			if ok && idx < 0 {
				idx += len(cl)
			}
			if ok && idx >= 0 && idx < len(cl) {
				current = cl[idx]
			} else {
				return "", false
			}
			continue
		}
		if cm, ok := current.(map[string]any); ok {
			if v, exists := cm[segment]; exists {
				current = v
				continue
			}
			return "", false
		}
		return stringify(current), true
	}
	return stringify(current), true
}

// stringify renders a decoded JSON scalar the way a Python-based agent backend does — None / True /
// False for null and booleans — because that is the literal text such a target echoes, and the
// evidence must match it. Whole numbers print without a trailing decimal.
func stringify(v any) string {
	switch t := v.(type) {
	case nil:
		return "None"
	case string:
		return t
	case bool:
		if t {
			return "True"
		}
		return "False"
	case float64:
		// JSON numbers decode as float64; a whole number renders without a decimal point.
		if t == float64(int64(t)) {
			return strconv.FormatInt(int64(t), 10)
		}
		return strconv.FormatFloat(t, 'g', -1, 64)
	default:
		return fmt.Sprint(t)
	}
}
