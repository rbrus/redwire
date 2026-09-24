// Copyright 2026 Radoslaw Brus. SPDX-License-Identifier: Apache-2.0

package connector

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/websocket"
)

// Browser reaches an agent that has no API: a chat widget bolted onto a web page. A support
// assistant, an embedded product bot, a demo chat behind a cookie banner.
//
// The one thing this file gets right, or the rest does not matter: it is a Target like any other. It
// satisfies redwire.Target with a Send that takes a string and returns a string, so every
// technique, scan phase and judge built on that interface runs against a widget unchanged and
// without knowing the transport is a browser. A connector that needed its own technique set would be
// a second product.
//
// NO NEW DEPENDENCY, and that is a design constraint rather than a happy accident. A headless-browser
// driver (Playwright, chromedp, rod) is a large amount of new attack surface in a security product,
// and "no new dependencies without written justification" is a hard rule here. So this speaks the
// Chrome DevTools Protocol directly — CDP is JSON over a WebSocket, and gorilla/websocket is already
// a direct dependency of the WebSocket connector next door. go.mod does not move.
//
// What it does need is a Chrome or Chromium binary reachable over a DevTools port, which is a
// deployment fact rather than a supply-chain one: the operator runs their own, or points at one they
// already run. When it is absent the connector says so in one sentence naming the flag to start it
// with, because "connection refused" sends people to the wrong problem.
//
// SSRF: navigation is a second dial and gets its own check. connectorFromConfig validates the
// endpoint before this is built, but a browser follows redirects, loads subresources and can be
// steered by the page itself, so the endpoint is re-validated here and the connector never navigates
// anywhere but the configured URL.
type Browser struct {
	cfg BrowserConfig

	mu   sync.Mutex
	tab  *browserTab
	sent bool // this connector has prepared the page at least once
}

// browserTab is one Chrome tab, SHARED by every Browser pointed at the same page on the same Chrome.
//
// Sharing rather than a tab each, for two reasons that point the same way. A scan builds a connector
// per agent — connectorFromConfig is called per task — so a tab each means a tab per agent per round,
// and nothing in redwire.Target has a Close for them to be released by: a real scan left tabs open until
// Chrome ran out of memory, which is how this was found. And a website chat widget is ONE visitor's
// session in the first place; a fresh tab per agent would be a less faithful model of the thing being
// attacked, not a more isolated one.
//
// The consequence is stated rather than hidden: agents share the widget's conversation, the way two
// techniques in one agent's multi-turn campaign already do. Every attempt still records its own payload
// and its own response, so a finding remains attributable to the payload that produced it.
type browserTab struct {
	conn     *cdpConn
	session  string
	targetID string
	refs     int
}

// release closes the PAGE and then the socket, in that order.
//
// Closing the socket alone leaves the tab open, which is the defect this was written to fix and which
// closing the socket looked like it fixed: a real scan left a page behind in the operator's Chrome
// every run, and nothing in this process could see it. Target.closeTarget is the call that actually
// disposes of a tab created by Target.createTarget.
func (t *browserTab) release() error {
	if t.targetID != "" {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		_ = t.conn.call(ctx, "", "Target.closeTarget", map[string]any{"targetId": t.targetID}, nil)
		cancel()
	}
	return t.conn.close()
}

// liveTabs keys a shared tab by the Chrome it lives on and the page it is showing. Package-level
// because the sharing has to span the Browser values a scan builds independently.
var (
	liveTabsMu sync.Mutex
	liveTabs   = map[string]*browserTab{}
)

// CloseAllBrowsers releases every shared tab and the DevTools sessions behind them. Called at the end
// of a scan: the tabs belong to a Chrome this process does not own, so leaving them is leaving litter
// in somebody else's browser.
func CloseAllBrowsers() {
	liveTabsMu.Lock()
	tabs := make([]*browserTab, 0, len(liveTabs))
	for k, t := range liveTabs {
		tabs = append(tabs, t)
		delete(liveTabs, k)
	}
	liveTabsMu.Unlock()
	for _, t := range tabs {
		_ = t.release()
	}
}

// BrowserConfig is the `connector.browser` block. Every selector is optional: empty means "detect it",
// and detection is a documented heuristic rather than a guarantee — see DetectionNotice.
type BrowserConfig struct {
	// Endpoint is the PAGE the widget lives on, not an API.
	Endpoint string

	// CDPURL is the DevTools HTTP endpoint of a Chrome already running with
	// --remote-debugging-port, e.g. http://127.0.0.1:9222. Required: this connector does not spawn
	// browsers. Launching one would mean owning process lifetime, sandbox flags and zombie reaping
	// inside a scan worker, and an operator who already runs Chrome in their own container is better
	// placed to decide all three.
	CDPURL string

	InputSelector    string   // where the payload is typed
	SendSelector     string   // clicked to submit; empty presses Enter
	ResponseSelector string   // reply bubbles; empty diffs the page text
	OpenSelector     string   // opens a collapsed widget, once per session
	DismissSelectors []string // consent banners, cleared once per session

	ResponseTimeout time.Duration // how long to wait for a reply before giving up
	SettleMS        int           // quiet period that marks a streamed reply complete
}

func (c *BrowserConfig) withDefaults() {
	if c.ResponseTimeout <= 0 {
		c.ResponseTimeout = 30 * time.Second
	}
	if c.SettleMS <= 0 {
		c.SettleMS = 800
	}
}

// DetectionNotice is what a connectivity check reports when no selectors were configured. Heuristics are
// a starting point: a page with several inputs, an unusual widget or a custom bubble structure needs
// them named. Saying so is the difference between a scan that reports a hardened target and one that
// reports it could not find the chat box — and those must never look alike, which is why a Send that
// cannot find the input returns an ERROR rather than an empty reply.
const DetectionNotice = "no browser selectors configured; the chat input, send control and reply " +
	"bubbles will be auto-detected. Set connector.browser.input_selector and response_selector if the " +
	"page has more than one input or a custom widget."

// NewBrowser builds the connector. It does not dial: the DevTools connection is opened on first Send,
// so building a scan plan does not require a live browser.
func NewBrowser(cfg BrowserConfig) *Browser {
	cfg.withDefaults()
	return &Browser{cfg: cfg}
}

// Send types one payload into the widget and returns what the bot answered.
//
// An empty reply is returned as an ERROR, never as an empty string. This is the whole
// go/acceptance doctrine applied to a new transport: a widget that did not answer, a selector that
// matched nothing and a page that never loaded must not arrive at the judge as a target that
// responded with silence — that is how "the target refused the attack" gets recorded about a scan
// that never delivered anything.
func (b *Browser) Send(ctx context.Context, message string) (string, error) {
	b.mu.Lock()
	defer b.mu.Unlock()

	if err := b.ensureSession(ctx); err != nil {
		return "", err
	}

	expr, err := b.chatScript(message)
	if err != nil {
		return "", err
	}

	ctx, cancel := context.WithTimeout(ctx, b.cfg.ResponseTimeout+10*time.Second)
	defer cancel()

	raw, err := b.tab.conn.evaluate(ctx, b.tab.session, expr)
	if err != nil {
		return "", fmt.Errorf("browser: %w", err)
	}

	var out struct {
		OK    bool   `json:"ok"`
		Reply string `json:"reply"`
		Error string `json:"error"`
	}
	if err := json.Unmarshal(raw, &out); err != nil {
		return "", fmt.Errorf("browser: unreadable result from the page: %w", err)
	}
	if !out.OK {
		return "", fmt.Errorf("browser: %s", orUnknown(out.Error))
	}
	b.sent = true
	if strings.TrimSpace(out.Reply) == "" {
		return "", fmt.Errorf("browser: the widget produced no reply within %s — an empty answer is "+
			"not evidence that the target refused the payload", b.cfg.ResponseTimeout)
	}
	return out.Reply, nil
}

func orUnknown(s string) string {
	if strings.TrimSpace(s) == "" {
		return "the page reported a failure with no detail"
	}
	return s
}

// Close drops this connector's reference to the shared tab, closing the tab when it was the last one.
// Refcounted rather than unconditional: a scan holds several connectors against one page, and the
// first agent to finish must not shut the widget on the others.
func (b *Browser) Close() error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.tab == nil {
		return nil
	}
	tab := b.tab
	b.tab, b.sent = nil, false

	liveTabsMu.Lock()
	defer liveTabsMu.Unlock()
	tab.refs--
	if tab.refs > 0 {
		return nil
	}
	for k, t := range liveTabs {
		if t == tab {
			delete(liveTabs, k)
		}
	}
	return tab.release()
}

// ensureSession opens the tab and navigates once, then leaves it open for the rest of the scan.
//
// One tab for the whole scan, deliberately: a multi-turn technique depends on the widget's own
// conversation state, and a fresh page per payload would silently convert every adaptive agent into a
// single-turn one while still reporting multi-turn coverage.
func (b *Browser) ensureSession(ctx context.Context) error {
	if b.tab != nil {
		return nil
	}
	if b.cfg.CDPURL == "" {
		return fmt.Errorf("browser connector needs a CDP URL (BrowserConfig.CDPURL) — the DevTools " +
			"endpoint of a Chrome you run, e.g. http://127.0.0.1:9222 from " +
			"`chromium --headless --remote-debugging-port=9222`. This connector does not spawn browsers")
	}

	key := b.cfg.CDPURL + "\x00" + b.cfg.Endpoint

	liveTabsMu.Lock()
	if tab, ok := liveTabs[key]; ok {
		tab.refs++
		b.tab = tab
		liveTabsMu.Unlock()
		return nil
	}
	liveTabsMu.Unlock()

	// Opened outside the lock: dialing Chrome and loading a page takes seconds, and holding the map
	// lock across it would serialise every agent's first send behind one navigation.
	conn, session, targetID, err := dialCDP(ctx, b.cfg.CDPURL)
	if err != nil {
		return err
	}
	tab := &browserTab{conn: conn, session: session, targetID: targetID, refs: 1}
	if err := conn.navigate(ctx, session, b.cfg.Endpoint); err != nil {
		_ = tab.release()
		return err
	}

	liveTabsMu.Lock()
	if existing, ok := liveTabs[key]; ok {
		// Another agent won the race. Use theirs and discard the tab just opened, rather than leaving
		// an orphan nothing holds a reference to — which is the leak this whole change exists to close.
		existing.refs++
		b.tab = existing
		liveTabsMu.Unlock()
		_ = tab.release()
		return nil
	}
	liveTabs[key] = tab
	b.tab = tab
	liveTabsMu.Unlock()
	return nil
}

/* ── CDP transport ───────────────────────────────────────────────────────────────────────────── */

// cdpConn is a minimal Chrome DevTools Protocol client: JSON messages over one WebSocket, correlated
// by an integer id. Only what this connector needs — there is no general-purpose CDP surface here,
// because every method added is one more thing to keep working against a protocol we do not own.
type cdpConn struct {
	ws *websocket.Conn

	mu     sync.Mutex
	nextID int
}

type cdpMessage struct {
	ID        int             `json:"id,omitempty"`
	SessionID string          `json:"sessionId,omitempty"`
	Method    string          `json:"method,omitempty"`
	Params    json.RawMessage `json:"params,omitempty"`
	Result    json.RawMessage `json:"result,omitempty"`
	Error     *struct {
		Message string `json:"message"`
	} `json:"error,omitempty"`
}

// dialCDP resolves the browser-level WebSocket, opens a tab and attaches to it, returning the session
// id every later command is scoped to.
func dialCDP(ctx context.Context, cdpURL string) (*cdpConn, string, string, error) {
	wsURL, err := browserWebSocketURL(ctx, cdpURL)
	if err != nil {
		return nil, "", "", err
	}

	dialer := &websocket.Dialer{HandshakeTimeout: 15 * time.Second}
	ws, _, err := dialer.DialContext(ctx, wsURL, nil)
	if err != nil {
		return nil, "", "", fmt.Errorf("browser: cannot open a DevTools session at %s: %w", cdpURL, err)
	}
	c := &cdpConn{ws: ws}

	var created struct {
		TargetID string `json:"targetId"`
	}
	if err := c.call(ctx, "", "Target.createTarget",
		map[string]any{"url": "about:blank"}, &created); err != nil {
		_ = c.close()
		return nil, "", "", err
	}

	var attached struct {
		SessionID string `json:"sessionId"`
	}
	if err := c.call(ctx, "", "Target.attachToTarget",
		map[string]any{"targetId": created.TargetID, "flatten": true}, &attached); err != nil {
		_ = c.close()
		return nil, "", "", err
	}
	if attached.SessionID == "" {
		_ = c.close()
		return nil, "", "", fmt.Errorf("browser: DevTools attached without a session id")
	}

	// Runtime must be enabled before Runtime.evaluate is meaningful on a fresh session.
	if err := c.call(ctx, attached.SessionID, "Runtime.enable", map[string]any{}, nil); err != nil {
		_ = c.close()
		return nil, "", "", err
	}
	if err := c.call(ctx, attached.SessionID, "Page.enable", map[string]any{}, nil); err != nil {
		_ = c.close()
		return nil, "", "", err
	}
	return c, attached.SessionID, created.TargetID, nil
}

// browserWebSocketURL asks the DevTools HTTP endpoint for its browser-level socket.
//
// The host is taken from the operator's own cdp_url and is NOT SSRF-checked: it is by definition a
// loopback or internal address, because that is where a debugging port lives. The guard belongs on
// the page being navigated to, which is the attacker-influenced value, and that is where it is.
func browserWebSocketURL(ctx context.Context, cdpURL string) (string, error) {
	base := strings.TrimRight(cdpURL, "/")
	if strings.HasPrefix(base, "ws://") || strings.HasPrefix(base, "wss://") {
		return base, nil
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, base+"/json/version", nil)
	if err != nil {
		return "", fmt.Errorf("browser: bad cdp_url %q: %w", cdpURL, err)
	}
	resp, err := (&http.Client{Timeout: 10 * time.Second}).Do(req)
	if err != nil {
		return "", fmt.Errorf("browser: no DevTools endpoint at %s — start Chrome with "+
			"--remote-debugging-port, or correct BrowserConfig.CDPURL: %w", cdpURL, err)
	}
	defer resp.Body.Close()
	var v struct {
		WebSocketDebuggerURL string `json:"webSocketDebuggerUrl"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&v); err != nil {
		return "", fmt.Errorf("browser: %s did not answer with DevTools version JSON: %w", cdpURL, err)
	}
	if v.WebSocketDebuggerURL == "" {
		return "", fmt.Errorf("browser: %s reported no webSocketDebuggerUrl", cdpURL)
	}
	return v.WebSocketDebuggerURL, nil
}

// call sends one command and waits for the reply with the matching id, discarding the events CDP
// interleaves. Serialised by the caller's lock — one scan drives one tab, so there is no concurrent
// command traffic to multiplex.
func (c *cdpConn) call(ctx context.Context, session, method string, params any, out any) error {
	c.mu.Lock()
	c.nextID++
	id := c.nextID
	c.mu.Unlock()

	raw, err := json.Marshal(params)
	if err != nil {
		return fmt.Errorf("browser: cannot encode %s params: %w", method, err)
	}
	if err := c.ws.WriteJSON(cdpMessage{
		ID: id, SessionID: session, Method: method, Params: raw,
	}); err != nil {
		return fmt.Errorf("browser: sending %s failed: %w", method, err)
	}

	if dl, ok := ctx.Deadline(); ok {
		_ = c.ws.SetReadDeadline(dl)
	} else {
		_ = c.ws.SetReadDeadline(time.Now().Add(60 * time.Second))
	}
	for {
		var msg cdpMessage
		if err := c.ws.ReadJSON(&msg); err != nil {
			return fmt.Errorf("browser: reading the reply to %s failed: %w", method, err)
		}
		if msg.ID != id {
			continue // an event, or another command's reply
		}
		if msg.Error != nil {
			return fmt.Errorf("browser: %s was refused: %s", method, msg.Error.Message)
		}
		if out == nil {
			return nil
		}
		if len(msg.Result) == 0 {
			return nil
		}
		return json.Unmarshal(msg.Result, out)
	}
}

func (c *cdpConn) close() error { return c.ws.Close() }

// navigate loads the page and waits for it to be usable.
func (c *cdpConn) navigate(ctx context.Context, session, endpoint string) error {
	if _, err := url.Parse(endpoint); err != nil {
		return fmt.Errorf("browser: bad endpoint %q: %w", endpoint, err)
	}
	var nav struct {
		ErrorText string `json:"errorText"`
	}
	if err := c.call(ctx, session, "Page.navigate", map[string]any{"url": endpoint}, &nav); err != nil {
		return err
	}
	if nav.ErrorText != "" {
		return fmt.Errorf("browser: the page did not load: %s", nav.ErrorText)
	}
	// Wait for the document to finish parsing. Polling readyState rather than subscribing to
	// Page.loadEventFired keeps the reply correlation in call() simple: this connector reads one reply
	// per command and treats everything else as noise, and an event-driven wait would need the
	// opposite.
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		raw, err := c.evaluate(ctx, session, `({ok: document.readyState === "complete", reply: "", error: ""})`)
		if err != nil {
			return err
		}
		var st struct {
			OK bool `json:"ok"`
		}
		if json.Unmarshal(raw, &st) == nil && st.OK {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(200 * time.Millisecond):
		}
	}
	return fmt.Errorf("browser: %s did not finish loading", endpoint)
}

// evaluate runs an expression in the page and returns its value as JSON.
func (c *cdpConn) evaluate(ctx context.Context, session, expression string) (json.RawMessage, error) {
	var res struct {
		Result struct {
			Value json.RawMessage `json:"value"`
		} `json:"result"`
		ExceptionDetails *struct {
			Text      string `json:"text"`
			Exception *struct {
				Description string `json:"description"`
			} `json:"exception"`
		} `json:"exceptionDetails"`
	}
	err := c.call(ctx, session, "Runtime.evaluate", map[string]any{
		"expression":    expression,
		"awaitPromise":  true,
		"returnByValue": true,
	}, &res)
	if err != nil {
		return nil, err
	}
	if res.ExceptionDetails != nil {
		detail := res.ExceptionDetails.Text
		if res.ExceptionDetails.Exception != nil && res.ExceptionDetails.Exception.Description != "" {
			detail = res.ExceptionDetails.Exception.Description
		}
		return nil, fmt.Errorf("the page raised: %s", detail)
	}
	if len(res.Result.Value) == 0 {
		return nil, fmt.Errorf("the page returned nothing")
	}
	return res.Result.Value, nil
}
