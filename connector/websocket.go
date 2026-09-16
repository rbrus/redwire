package connector

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/websocket"
)

// WebSocket reaches an agent over a persistent WebSocket connection — the shape many
// chat gateways use.
//
// Unlike REST and MCP it holds a CONNECTION, not a request: the same socket carries the whole
// conversation, which is what lets a multi-turn technique keep server-side session state. That is
// also why reconnection matters — a dropped socket mid-scan must not read as a target that stopped
// answering, so a send re-dials once before reporting failure.
//
// gorilla/websocket rather than a hand-rolled client: this is a security product, and implementing
// frame masking and continuation by hand is more attack surface than a vetted library. It is
// already in the module graph (a transitive dependency of ADK), so this adds no new module — it
// only promotes one to direct.
type WebSocket struct {
	url     string
	auth    Auth
	timeout time.Duration
	dialer  *websocket.Dialer

	mu   sync.Mutex
	conn *websocket.Conn
}

// NewWebSocket builds a connector. The URL may be given as http(s):// and is normalised to ws(s)://
// so a target config written for REST can be pointed at a socket without editing.
//
// The optional dialer is how a self-host operator scanning a private target opts out of the SSRF pin
// (PrivateTargetWSDialer); omitted, the socket is pinned like every other transport here. Variadic
// rather than a fourth parameter so no existing call site has to change to get the guard.
func NewWebSocket(rawURL string, auth Auth, timeout time.Duration, dialer ...*websocket.Dialer) *WebSocket {
	if timeout == 0 {
		timeout = 30 * time.Second
	}
	d := GuardedWSDialer(timeout)
	if len(dialer) > 0 && dialer[0] != nil {
		d = dialer[0]
	}
	return &WebSocket{
		url: normaliseWSURL(rawURL), auth: auth, timeout: timeout,
		dialer: d,
	}
}

func normaliseWSURL(u string) string {
	switch {
	case strings.HasPrefix(u, "https://"):
		return "wss://" + strings.TrimPrefix(u, "https://")
	case strings.HasPrefix(u, "http://"):
		return "ws://" + strings.TrimPrefix(u, "http://")
	default:
		return u
	}
}

func (w *WebSocket) headers() http.Header {
	h := http.Header{}
	switch w.auth.Type {
	case AuthBearer:
		h.Set("Authorization", "Bearer "+w.auth.Token)
	case AuthAPIKey:
		h.Set(w.auth.APIKeyHeader, w.auth.APIKeyValue)
	}
	return h
}

// connect dials, or returns the live connection. Callers hold the mutex.
func (w *WebSocket) connect(ctx context.Context) (*websocket.Conn, error) {
	if w.conn != nil {
		return w.conn, nil
	}
	conn, resp, err := w.dialer.DialContext(ctx, w.url, w.headers())
	if err != nil {
		// A handshake rejected with 401/403 is the one failure that stops a scan: we cannot reach
		// the target as ourselves. Everything else is reported as text and scored, matching REST.
		if resp != nil && (resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden) {
			return nil, &AuthError{StatusCode: resp.StatusCode}
		}
		return nil, err
	}
	w.conn = conn
	return conn, nil
}

// Send delivers one payload over the socket and returns the next message the target sends.
//
// One retry on a transport failure, because a socket that dropped between turns is an artifact of
// the connection, not an answer from the target — reporting it as the target's response would put
// a lie in the evidence.
// Every failure below returns an ERROR rather than a "[WS ERROR] …" string. The marker form handed
// the caller a transport failure dressed as the agent's own words, so the attempt carried no
// engine.Attempt.Error and a ws:// endpoint that never accepted a connection was reported as a target
// that received and withstood every technique. The attack loops continue on an error, so nothing is
// lost by saying what happened.
func (w *WebSocket) Send(ctx context.Context, message string) (string, error) {
	w.mu.Lock()
	defer w.mu.Unlock()

	for attempt := 0; attempt < 2; attempt++ {
		conn, err := w.connect(ctx)
		if err != nil {
			var authErr *AuthError
			if asAuth(err, &authErr) {
				return "", authErr
			}
			if attempt == 0 {
				continue
			}
			return "", fmt.Errorf("ws dial: %w", err)
		}

		deadline := time.Now().Add(w.timeout)
		_ = conn.SetWriteDeadline(deadline)
		if err := conn.WriteMessage(websocket.TextMessage, []byte(message)); err != nil {
			w.reset()
			if attempt == 0 {
				continue // the socket went away between turns: re-dial once
			}
			return "", fmt.Errorf("ws write: %w", err)
		}

		_ = conn.SetReadDeadline(deadline)
		_, payload, err := conn.ReadMessage()
		if err != nil {
			w.reset()
			if attempt == 0 {
				continue
			}
			return "", fmt.Errorf("ws read: %w", err)
		}
		return string(payload), nil
	}
	return "", fmt.Errorf("ws: target unreachable after retry")
}

// reset drops the connection so the next send re-dials.
func (w *WebSocket) reset() {
	if w.conn != nil {
		_ = w.conn.Close()
		w.conn = nil
	}
}

// Close releases the socket at the end of a scan.
func (w *WebSocket) Close() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.conn == nil {
		return nil
	}
	err := w.conn.Close()
	w.conn = nil
	return err
}

// SendWithoutAuth opens a FRESH socket carrying no credentials and sends one message — the probe
// for a gateway that implicitly trusts local or unauthenticated connections. It is a distinct
// method rather than a flag because it must never reuse the authenticated connection: the whole
// point is to learn what the target does for a caller who proved nothing.
func (w *WebSocket) SendWithoutAuth(ctx context.Context, message string) (string, error) {
	conn, _, err := w.dialer.DialContext(ctx, w.url, nil)
	if err != nil {
		return fmt.Sprintf("[WS ERROR] %v", err), nil
	}
	defer conn.Close()

	deadline := time.Now().Add(w.timeout)
	_ = conn.SetWriteDeadline(deadline)
	if err := conn.WriteMessage(websocket.TextMessage, []byte(message)); err != nil {
		return fmt.Sprintf("[WS ERROR] write: %v", err), nil
	}
	_ = conn.SetReadDeadline(deadline)
	_, payload, err := conn.ReadMessage()
	if err != nil {
		return fmt.Sprintf("[WS ERROR] read: %v", err), nil
	}
	return string(payload), nil
}

func asAuth(err error, target **AuthError) bool {
	e, ok := err.(*AuthError)
	if ok {
		*target = e
	}
	return ok
}
