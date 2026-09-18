// Copyright 2026 Radoslaw Brus. SPDX-License-Identifier: Apache-2.0

// The guarded client, tested as the two attacks a validate-then-dial guard does not survive:
// a name that rebinds between the check and the connect, and a 302 into the internal network.
package ssrf

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// internalService stands in for the thing an SSRF is aimed at: something on loopback that answers
// with a secret. httptest always binds 127.0.0.1, so its address is a private one by construction.
func internalService(t *testing.T) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("ya29.INSTANCE-CREDENTIAL"))
	}))
	t.Cleanup(srv.Close)
	return srv
}

func TestTheGuardedClientWillNotDialAnInternalAddress(t *testing.T) {
	internal := internalService(t)

	resp, err := NewHTTPClient(5 * time.Second).Get(internal.URL)
	if err == nil {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<10))
		resp.Body.Close()
		t.Fatalf("the client reached loopback and read %q", body)
	}
	if !strings.Contains(err.Error(), "Private/internal") {
		t.Errorf("refused for the wrong reason: %v", err)
	}
}

func TestARedirectIntoTheInternalNetworkIsRefused(t *testing.T) {
	// THE case a validate-then-dial guard misses entirely: the caller-supplied URL is fine, and the
	// target answers 302 to somewhere it is not. http.Client follows that by default.
	//
	// Both httptest servers bind 127.0.0.1, so the two hops differ only by PORT — and since a port
	// change is no longer read as a host change (see sameSite), the credential rule has nothing to
	// say here and the ADDRESS half is what refuses. That is the right division of labour and worth
	// pinning: this test is about a redirect reaching loopback, which is exactly what the address
	// half is for. The credential half is exercised on its own below, on hops between real names.
	internal := internalService(t)
	open := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, internal.URL+"/latest/meta-data/", http.StatusFound)
	}))
	t.Cleanup(open.Close)

	// The connection guard is deliberately out of the way here — a plain dialer — so the only thing
	// that can refuse the second hop is the redirect check. Without that isolation the test would
	// pass for the wrong reason and tell us nothing about redirects.
	c := newHTTPClient(5*time.Second, (&net.Dialer{}).DialContext)

	resp, err := c.Get(open.URL)
	if err == nil {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<10))
		resp.Body.Close()
		t.Fatalf("the redirect was followed into loopback and returned %q", body)
	}
	if !strings.Contains(err.Error(), "Private/internal") {
		t.Errorf("refused for the wrong reason: %v", err)
	}
}

func TestARedirectThatKeepsTheHostButResolvesInternallyIsRefused(t *testing.T) {
	// The address half of the per-hop check, isolated. The hop stays on the host the previous one
	// was sent to, so the cross-host refusal has nothing to say, and the name answers with an
	// internal address — DNS rebinding aimed at the redirect rather than at the first request.
	withResolver(t, fakeResolver{addrs: ips("10.0.0.5")})
	prev, _ := http.NewRequest(http.MethodGet, "http://agent.example.com/chat", nil)
	next, _ := http.NewRequest(http.MethodGet, "http://agent.example.com/latest/meta-data/", nil)
	err := CheckRedirect(next, []*http.Request{prev})
	if err == nil {
		t.Fatal("a redirect onto an internal address was allowed")
	}
	if !strings.Contains(err.Error(), "Private/internal") {
		t.Errorf("refused for the wrong reason: %v", err)
	}
}

func TestARedirectToABlockedHostnameIsRefused(t *testing.T) {
	// The metadata name resolves PUBLICLY here, so no address check can catch it — only the
	// name blocklist, applied per hop, can. The previous hop is put on the same name so the
	// cross-host refusal cannot answer first and hide whether the blocklist still runs.
	withResolver(t, fakeResolver{addrs: ips("203.0.113.9")})
	prev, _ := http.NewRequest(http.MethodGet, "http://metadata.google.internal/", nil)
	next, _ := http.NewRequest(http.MethodGet, "http://metadata.google.internal/computeMetadata/v1/", nil)
	err := CheckRedirect(next, []*http.Request{prev})
	if err == nil {
		t.Fatal("a redirect to the metadata name was followed")
	}
	if !strings.Contains(err.Error(), "hostname is not allowed") {
		t.Errorf("refused for the wrong reason: %v", err)
	}
}

func TestACrossHostRedirectCannotCarryTheCredentialOrThePayload(t *testing.T) {
	// Validating WHERE a hop goes says nothing about WHAT rides on it, and the destination here is
	// genuinely public — every address and name check passes. Go then copies every header except
	// Authorization onto the new request and, on 307, replays the body. Our credential does not
	// travel as Authorization (an api_key target names its own header) and the body is the attack
	// template, so a target answering 307 exfiltrates both unless the host change is refused.
	withResolver(t, fakeResolver{addrs: ips("203.0.113.9")})

	type carried struct{ key, body string }
	got := make(chan carried, 4)
	collector := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(io.LimitReader(r.Body, 1<<12))
		got <- carried{key: r.Header.Get("X-API-Key"), body: string(b)}
	}))
	t.Cleanup(collector.Close)

	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "http://collector.example/collect", http.StatusTemporaryRedirect)
	}))
	t.Cleanup(origin.Close)

	// Both hops reach a real listener, and the connection guard is out of the way, so the redirect
	// check is the only thing in the process that can refuse this.
	dial := func(ctx context.Context, network, address string) (net.Conn, error) {
		if strings.HasPrefix(address, "collector.example:") {
			address = collector.Listener.Addr().String()
		}
		return (&net.Dialer{}).DialContext(ctx, network, address)
	}
	c := newHTTPClient(5*time.Second, dial)

	req, err := http.NewRequest(http.MethodPost, origin.URL, strings.NewReader(`{"input":"ATTACK-TEMPLATE"}`))
	if err != nil {
		t.Fatalf("build request: %v", err)
	}
	req.Header.Set("X-API-Key", "CUSTOMER-AGENT-CREDENTIAL")
	resp, err := c.Do(req)
	if err == nil {
		resp.Body.Close()
	}
	select {
	case c := <-got:
		t.Fatalf("the redirect reached another host carrying key=%q body=%q", c.key, c.body)
	default:
	}
	if err == nil {
		t.Fatal("a cross-host redirect was followed")
	}
}

func TestASameHostRedirectIsStillFollowed(t *testing.T) {
	// The refusal is about a change of host, not about redirects. A target that moves us within its
	// own origin — a new path, or the http->https upgrade — is ordinary, and refusing that would be
	// an outage dressed as a guard.
	withResolver(t, fakeResolver{addrs: ips("203.0.113.9")})
	prev, _ := http.NewRequest(http.MethodPost, "http://agent.example.com/chat", nil)
	for _, to := range []string{
		"http://agent.example.com/v2/chat",
		"https://agent.example.com/chat",
	} {
		next, _ := http.NewRequest(http.MethodPost, to, nil)
		if err := CheckRedirect(next, []*http.Request{prev}); err != nil {
			t.Errorf("a same-host redirect to %s was refused: %v", to, err)
		}
	}
}

func TestTheHopsAWorkingTargetActuallyMakesAreStillFollowed(t *testing.T) {
	// A guard that refuses a legitimate target gets switched off, and switching this one off drops
	// the credential rule with it. These three are the hops real deployments make and none of them
	// moves the credential to anyone else's machine: apex<->www is one name pair under one owner,
	// and a port change stays on the host we were already talking to — whoever controls that host
	// controls all of its ports, so nothing new is exposed.
	withResolver(t, fakeResolver{addrs: ips("203.0.113.9")})
	for _, hop := range [][2]string{
		{"https://agent.example.com/chat", "https://www.agent.example.com/chat"},
		{"https://www.agent.example.com/chat", "https://agent.example.com/chat"},
		{"http://agent.example.com:80/chat", "https://agent.example.com:443/chat"},
		{"http://agent.example.com:8080/chat", "http://agent.example.com:9443/chat"},
	} {
		prev, _ := http.NewRequest(http.MethodPost, hop[0], nil)
		next, _ := http.NewRequest(http.MethodPost, hop[1], nil)
		if err := CheckRedirect(next, []*http.Request{prev}); err != nil {
			t.Errorf("%s -> %s was refused: %v", hop[0], hop[1], err)
		}
	}
}

func TestWideningTheHostRuleDidNotReopenTheExfiltration(t *testing.T) {
	// The test that matters for the widening above. A sibling subdomain is NOT the same host: on a
	// shared-hosting name (customer.pages.dev, victim.github.io) the neighbour is a stranger, so a
	// same-registrable-domain rule would have handed the credential away. Only the exact name and
	// its www form pass.
	withResolver(t, fakeResolver{addrs: ips("203.0.113.9")})
	for _, hop := range [][2]string{
		{"https://agent.example.com/chat", "https://collector.example/collect"},
		{"https://agent.example.com/chat", "https://evil.example.com/collect"},
		{"https://www.agent.example.com/chat", "https://evil.agent.example.com/collect"},
		{"https://agent.example.com/chat", "https://agent.example.com.evil.test/collect"},
		{"https://www.example.com/chat", "https://com/collect"},
	} {
		prev, _ := http.NewRequest(http.MethodPost, hop[0], nil)
		next, _ := http.NewRequest(http.MethodPost, hop[1], nil)
		if err := CheckRedirect(next, []*http.Request{prev}); err == nil {
			t.Errorf("%s -> %s was allowed", hop[0], hop[1])
		}
	}
}

func TestTheCredentialHalfCanBeUsedWithoutTheAddressHalf(t *testing.T) {
	// What PrivateTargetClient needs: the self-host operator opted out of the ADDRESS block, not out
	// of the rule about what a hop carries. So the exported credential half has to refuse a host
	// change while saying nothing about a loopback destination.
	prev, _ := http.NewRequest(http.MethodPost, "http://127.0.0.1:9000/chat", nil)
	same, _ := http.NewRequest(http.MethodPost, "http://127.0.0.1:9100/chat", nil)
	if err := CheckSameHostRedirect(same, []*http.Request{prev}); err != nil {
		t.Errorf("a hop within a private target was refused: %v", err)
	}
	away, _ := http.NewRequest(http.MethodPost, "http://collector.example/collect", nil)
	if err := CheckSameHostRedirect(away, []*http.Request{prev}); err == nil {
		t.Error("a private target was allowed to redirect the credential to another host")
	}
	// The hop cap lives here too: it belongs to whichever CheckRedirect a client installs, and
	// installing one replaces http.Client's own bounded default.
	if err := CheckSameHostRedirect(same, make([]*http.Request, maxRedirects)); err == nil {
		t.Errorf("hop %d was allowed; the chain is unbounded", maxRedirects+1)
	}
}

func TestTheDialIsPinnedToTheAddressThatWasChecked(t *testing.T) {
	// The rebinding window ValidatePublicURL documents but does not close: the name answered
	// publicly a moment ago and answers with loopback now. What the guard has to check is the
	// address the kernel is about to connect to, not the one DNS offered earlier.
	internal := internalService(t)
	rebound := internal.Listener.Addr().String()

	d := NewDialer(2 * time.Second)
	conn, err := d.DialContext(context.Background(), "tcp", rebound)
	if err == nil {
		conn.Close()
		t.Fatalf("the guarded dialer connected to %s", rebound)
	}

	// The control: an unguarded dialer reaches it, so the refusal above is the guard and not a
	// listener that was never there.
	plain, err := (&net.Dialer{Timeout: 2 * time.Second}).DialContext(context.Background(), "tcp", rebound)
	if err != nil {
		t.Fatalf("the test's own listener was unreachable: %v", err)
	}
	plain.Close()
}

func TestARedirectToPublicSpaceIsStillFollowed(t *testing.T) {
	// The other half of the guard's job. A per-hop check that refuses every hop is an outage, and
	// the redirect case is exactly where that would be easy to ship and hard to notice.
	withResolver(t, fakeResolver{addrs: ips("203.0.113.9")})
	next, _ := http.NewRequest(http.MethodGet, "https://agent.example.com/v2/chat", nil)
	if err := CheckRedirect(next, nil); err != nil {
		t.Errorf("a redirect to a public host was refused: %v", err)
	}
}

func TestTheRedirectChainIsBounded(t *testing.T) {
	// Supplying a CheckRedirect replaces http.Client's default one, and the 10-hop cap lives inside
	// that default — so replacing it without re-imposing the cap turns a redirect loop into an
	// unbounded one.
	withResolver(t, fakeResolver{addrs: ips("203.0.113.9")})
	next, _ := http.NewRequest(http.MethodGet, "https://agent.example.com/", nil)
	via := make([]*http.Request, maxRedirects)
	if err := CheckRedirect(next, via); err == nil {
		t.Errorf("hop %d was allowed; the chain is unbounded", maxRedirects+1)
	}
}

func TestThePinReadsEveryAddressShapeTheDialerCanHandIt(t *testing.T) {
	// pinControl is the last check before a socket opens, so it is tested directly rather than only
	// through a dial: the IPv4-mapped IPv6 form is the one that looks public to a careless string
	// check and is loopback to the kernel.
	blocked := []string{
		"127.0.0.1:80", "10.1.2.3:443", "169.254.169.254:80", "0.0.0.0:8080",
		"100.64.0.1:80", "[::1]:80", "[fe80::1]:80", "[::ffff:127.0.0.1]:80",
	}
	for _, addr := range blocked {
		if err := pinControl("tcp", addr, nil); err == nil {
			t.Errorf("pinControl allowed %s", addr)
		}
	}
	for _, addr := range []string{"203.0.113.9:443", "[2001:db8::1]:443"} {
		if err := pinControl("tcp", addr, nil); err != nil {
			t.Errorf("pinControl refused public %s: %v", addr, err)
		}
	}
	// Something that is not an address at all fails closed rather than falling through.
	for _, addr := range []string{"example.com:80", "garbage", ""} {
		if err := pinControl("tcp", addr, nil); err == nil {
			t.Errorf("pinControl allowed the unreadable address %q", addr)
		}
	}
}
