// Copyright 2026 Radoslaw Brus. SPDX-License-Identifier: Apache-2.0

package connector

import (
	"net/http"
	"time"

	"github.com/gorilla/websocket"
	"github.com/rbrus/redwire/ssrf"
)

// What every transport in this package dials through, and the one place the choice is made.
//
// A connector's endpoint is the least trusted string in the system: it arrives in a target config
// or a probe body, it is chosen by whoever is pointing the scanner at a system, and the process
// holding it runs inside a trusted network. So the default here is the SSRF-pinned client — resolved
// address checked at connect time, every redirect hop re-validated — and a caller who wants the
// unpinned one has to name it.
//
// That direction matters more than it looks. An opt-in guard reads the same as an opt-out one in
// review and behaves like no guard at all in production. Passing nil is the common case and nil now
// means guarded.
//
// The exception is real and narrow: an operator red-teaming their OWN agent on localhost. Only the
// call sites that have already established the endpoint is operator-chosen — the person typing it IS
// the trust boundary — are entitled to it, and they must ASK, by name, for PrivateTargetClient.

// GuardedClient is the default: SSRF-pinned on connect, redirects re-validated per hop.
func GuardedClient(timeout time.Duration) *http.Client {
	return ssrf.NewHTTPClient(defaultTimeout(timeout))
}

// PrivateTargetClient dials WITHOUT the address guard. Only for an operator scanning an agent on
// their own loopback or LAN, where the person typing the endpoint is the trust boundary. It must
// never be reached on a path where the endpoint is a stranger's string.
//
// It keeps the redirect rule, and that is the whole point of it being a separate constructor rather
// than a bare http.Client. Opting into a PRIVATE ADDRESS is not opting into handing the caller's
// credential and request body to a third host: one `307 -> https://attacker.example/collect`
// from a target that has been taken over replays the body and copies every non-Authorization header,
// and an api_key target's credential travels under a header the caller named. That threat model is
// the hostile target, not the operator-chosen endpoint, so it does not go with the address pin. See
// ssrf.CheckSameHostRedirect.
func PrivateTargetClient(timeout time.Duration) *http.Client {
	return &http.Client{
		Timeout:       defaultTimeout(timeout),
		CheckRedirect: ssrf.CheckSameHostRedirect,
	}
}

// GuardedWSDialer is the WebSocket equivalent. gorilla dials through NetDialContext when one is set,
// and does its own TLS on top of that connection, so pinning here covers ws:// and wss:// alike.
func GuardedWSDialer(timeout time.Duration) *websocket.Dialer {
	t := defaultTimeout(timeout)
	return &websocket.Dialer{
		HandshakeTimeout: t,
		NetDialContext:   ssrf.NewDialer(t).DialContext,
	}
}

// PrivateTargetWSDialer is GuardedWSDialer's escape hatch, on the same terms.
//
// There is no redirect half to keep here: gorilla treats any response that is not 101 as a failed
// handshake and returns ErrBadHandshake without following it, so a 307 from a WebSocket target
// cannot carry anything anywhere. Said out loud because the asymmetry with PrivateTargetClient
// otherwise reads as an omission.
func PrivateTargetWSDialer(timeout time.Duration) *websocket.Dialer {
	return &websocket.Dialer{HandshakeTimeout: defaultTimeout(timeout)}
}

func defaultTimeout(t time.Duration) time.Duration {
	if t <= 0 {
		return 30 * time.Second
	}
	return t
}
