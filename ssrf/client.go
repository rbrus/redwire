// Copyright 2026 Radoslaw Brus. SPDX-License-Identifier: Apache-2.0

package ssrf

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"syscall"
	"time"
)

// The guarded client: the half of this package that closes the window ValidatePublicURL only
// documents.
//
// ValidatePublicURL answers a question about a moment that has already passed — what the name
// resolved to when we asked. Two things happen after it returns and before any byte reaches a
// target, and neither is visible to it:
//
//   - The name is resolved AGAIN by the dialer, and can answer differently. That is DNS rebinding,
//     and it is a two-line attack against a validate-then-dial guard.
//   - The target replies 302. http.Client follows redirects by default, so a target that passes
//     every check can hand the client an internal URL and have it fetched — the check never runs on
//     the hop that matters. A redirect also decides what the client CARRIES to the next host, which
//     is a separate question from whether that host is allowed; see checkSameHost.
//
// So the guard has to live at the two places the decision is actually made: net.Dialer.Control,
// which the kernel calls with the CONCRETE address it is about to connect to, and CheckRedirect,
// which runs before each subsequent hop is sent. Both reuse checkIP and ValidatePublicURL — there
// is still exactly one blocklist.
//
// One deliberate omission: the guarded transport does NOT honour HTTP_PROXY. Through a proxy the
// address dialled is the proxy's, so Control would be checking the wrong thing and the pin would be
// a control that looks like a control. A deployment that needs an egress proxy has to say so
// somewhere this guard can see it.

// maxRedirects mirrors the cap http.Client applies through its own default CheckRedirect. Supplying
// a CheckRedirect replaces that default outright, so without this line a redirect loop is unbounded.
const maxRedirects = 10

// dialContextFunc is net.Dialer.DialContext's shape, named so the client constructor can take one.
type dialContextFunc func(ctx context.Context, network, address string) (net.Conn, error)

// pinControl is called by the kernel path with the address the socket is about to connect to, after
// DNS and after Happy Eyeballs picked a candidate — once per candidate. This is the only place in
// the process that knows the real destination, which is what makes it the only place a pin can be.
func pinControl(_, address string, _ syscall.RawConn) error {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return fail("Could not read the address being dialled.")
	}
	ip := net.ParseIP(host)
	if ip == nil {
		// The dialer hands Control a literal; anything else means we cannot tell what we are
		// connecting to, and an address we cannot check is not one we dial.
		return fail("Could not read the address being dialled.")
	}
	return checkIP(ip)
}

// NewDialer is a net.Dialer that refuses an internal destination at connect time. Use it anywhere a
// caller-supplied endpoint is dialled without going through NewHTTPClient — the WebSocket
// connector, for one, dials on its own.
func NewDialer(timeout time.Duration) *net.Dialer {
	return &net.Dialer{
		Timeout:   timeout,
		KeepAlive: 30 * time.Second,
		Control:   pinControl,
	}
}

// NewHTTPClient is the client every outbound call to a caller-supplied endpoint should use: pinned
// on connect, re-checked on every redirect hop, and bounded by timeout end to end.
func NewHTTPClient(timeout time.Duration) *http.Client {
	return newHTTPClient(timeout, NewDialer(timeout).DialContext)
}

// newHTTPClient takes the dialer as a parameter so a test can put the connection guard out of the
// way and leave the redirect guard as the only thing that can refuse a hop. Two guards that can
// cover for each other cannot tell you which one you actually have.
//
// The transport is cloned from the standard one so the connection-pool and header limits stay
// whatever the runtime considers current; only the two fields that decide where bytes go are
// replaced.
func newHTTPClient(timeout time.Duration, dial dialContextFunc) *http.Client {
	t := http.DefaultTransport.(*http.Transport).Clone()
	t.DialContext = dial
	t.Proxy = nil // see the package note above: a proxy hides the address the pin exists to check
	return &http.Client{
		Timeout:       timeout,
		Transport:     t,
		CheckRedirect: CheckRedirect,
	}
}

// CheckRedirect validates the hop a redirect is about to take. Exported so a call site that builds
// its own client for other reasons can still get this half.
//
// Two questions, and the second one is the one a per-hop URL check does not ask. WHERE the hop goes
// is ValidatePublicURL's — run in full per hop, not just an address check, because a 302 to
// http://metadata.google.internal/ names a host whose address may be perfectly public from where we
// resolve it, and only the name blocklist catches that one. WHAT rides on the hop is decided by
// net/http, not by us, and that is CheckSameHostRedirect's.
func CheckRedirect(req *http.Request, via []*http.Request) error {
	// Before the destination is even resolved: a hop we will not take is not a name we should be
	// asking DNS about, and refusing here means the credential decision does not depend on how the
	// address check happens to answer.
	if err := CheckSameHostRedirect(req, via); err != nil {
		return err
	}
	return ValidatePublicURL(req.Context(), req.URL.String())
}

// CheckSameHostRedirect is the credential half of the redirect guard, usable without the address
// half — the hop cap and the rule about what a hop may CARRY, and nothing about where it goes.
//
// It exists because the two decisions were being traded away together. A caller who opts into a
// private target is consenting to the ADDRESS of their target being private; they are not consenting
// to their credential and their request body being replayed to a third host on a 307. Those threat
// models are not the same one — the address pin protects the caller's network from an operator-chosen
// endpoint, this protects the caller's secrets from a target that has been taken over — so
// connector.PrivateTargetClient drops the first and keeps this.
//
// The hop cap belongs here rather than only in CheckRedirect: installing ANY CheckRedirect replaces
// http.Client's default one, and the cap lives inside that default.
func CheckSameHostRedirect(req *http.Request, via []*http.Request) error {
	if len(via) >= maxRedirects {
		return fmt.Errorf("stopped after %d redirects", maxRedirects)
	}
	if req == nil || req.URL == nil {
		return fail("Invalid endpoint URL.")
	}
	return checkSameHost(req, via)
}

// checkSameHost refuses a hop that leaves the host the previous one was sent to.
//
// A destination can be entirely public and still be the wrong place for what net/http will carry
// there. Across a host change Go strips Authorization and copies every OTHER header verbatim, and on
// 307/308 it replays the request body. Neither of those defaults protects the caller: an api_key
// target sends its credential under a header the caller named (`X-API-Key` by default), which Go has
// no reason to special-case, and the body is whatever payload was being sent. So a single
// `307 -> https://attacker.example/collect` from a target — or from whoever has taken that target
// over, which is the threat model here — hands over both, having passed every check that only looks
// at where the hop goes.
func checkSameHost(req *http.Request, via []*http.Request) error {
	if len(via) == 0 {
		return nil
	}
	prev := via[len(via)-1]
	if prev == nil || prev.URL == nil || !sameSite(prev.URL, req.URL) {
		return fail("Redirect to a different host is refused.")
	}
	return nil
}

// sameSite decides which hops keep the credential, and it is drawn deliberately narrowly.
//
// The comparison is the HOSTNAME, not URL.Host, so a port change is not a host change. Whoever
// controls a host controls all of its ports, so moving between them exposes nothing that was not
// already exposed — and it is the ordinary shape on the two paths that matter most here: a self-host
// operator whose agent redirects loopback:9000 to loopback:9100, and the explicit `:80 -> :443`
// upgrade a lot of front ends write out in full. Comparing URL.Host refused both, and a guard that
// breaks a working target gets switched off, which loses the credential rule entirely — that trade is
// worse than the one it was protecting against.
//
// Beyond that, only the apex<->www pair. The tempting generalisation is same-registrable-domain, and
// it is wrong twice over: it needs a public-suffix list (a new dependency in a security product, and
// an approximation of one is a blocklist that is quietly incomplete), and on shared-hosting names the
// registrable domain is not an owner at all — victim.github.io and attacker.github.io share one, so
// the rule would hand the credential to a stranger. A sibling subdomain stays refused.
func sameSite(prev, next *url.URL) bool {
	p := strings.ToLower(prev.Hostname())
	n := strings.ToLower(next.Hostname())
	if p == "" || n == "" {
		return false
	}
	return p == n || apexAndWWW(p, n) || apexAndWWW(n, p)
}

// apexAndWWW reports whether www is exactly the www form of apex. The dot requirement keeps the pair
// to names that can actually hold a record: without it "www.com" would be treated as the www form of
// the public suffix "com".
func apexAndWWW(apex, www string) bool {
	return strings.Contains(apex, ".") && www == "www."+apex
}
