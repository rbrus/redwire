// Copyright 2026 Radoslaw Brus. SPDX-License-Identifier: Apache-2.0

// The SSRF guard, tested as the attacks it exists to refuse rather than as a function that returns
// errors. A blocklist with a hole in it looks exactly like one without.
package ssrf

import (
	"context"
	"errors"
	"net"
	"strings"
	"testing"
)

// fakeResolver answers with whatever the test decides the name resolves to.
type fakeResolver struct {
	addrs []net.IPAddr
	err   error
}

func (f fakeResolver) LookupIPAddr(context.Context, string) ([]net.IPAddr, error) {
	return f.addrs, f.err
}

func withResolver(t *testing.T, r Resolver) {
	t.Helper()
	prev := DefaultResolver
	DefaultResolver = r
	t.Cleanup(func() { DefaultResolver = prev })
}

func ips(list ...string) []net.IPAddr {
	out := make([]net.IPAddr, 0, len(list))
	for _, s := range list {
		out = append(out, net.IPAddr{IP: net.ParseIP(s)})
	}
	return out
}

func TestALiteralPrivateAddressIsRefused(t *testing.T) {
	for _, raw := range []string{
		"http://127.0.0.1/",
		"http://10.1.2.3/",
		"http://172.16.0.1/",
		"http://192.168.1.1/",
		"http://[::1]/",
		"http://[fc00::1]/",
	} {
		if err := ValidatePublicURL(context.Background(), raw); err == nil {
			t.Errorf("%s was allowed", raw)
		}
	}
}

func TestTheCloudMetadataAddressIsRefused(t *testing.T) {
	// 169.254.169.254 is the single most valuable SSRF target on any cloud: it hands out the
	// instance's own credentials to anything that asks.
	if err := ValidatePublicURL(context.Background(), "http://169.254.169.254/latest/meta-data/"); err == nil {
		t.Error("the cloud metadata endpoint was allowed")
	}
}

func TestMetadataByNameIsRefusedToo(t *testing.T) {
	// Blocking the IP is not enough when the name resolves to it from inside the VPC — and on GCP
	// the name works without the address.
	withResolver(t, fakeResolver{addrs: ips("203.0.113.9")}) // even answering PUBLICLY
	for _, host := range []string{
		"http://metadata.google.internal/computeMetadata/v1/",
		"http://metadata.google.internal./computeMetadata/v1/",
		"http://localhost/",
		"http://localhost./",
		"http://LOCALHOST/",
		"http://localhost.localdomain/",
		"http://localhost.localdomain./",
	} {
		if err := ValidatePublicURL(context.Background(), host); err == nil {
			t.Errorf("%s was allowed", host)
		}
	}
}

func TestAPublicAddressIsAllowed(t *testing.T) {
	// The guard has to let real traffic through, or it is not a guard, it is an outage.
	withResolver(t, fakeResolver{addrs: ips("203.0.113.9")})
	if err := ValidatePublicURL(context.Background(), "https://agent.example.com/chat"); err != nil {
		t.Errorf("a public endpoint was refused: %v", err)
	}
}

func TestEveryResolvedAddressIsChecked(t *testing.T) {
	// THE rebinding case. A name that answers with one public and one private address is the
	// attack, not an accident — checking only the first would pass it.
	withResolver(t, fakeResolver{addrs: ips("203.0.113.9", "10.0.0.5")})
	if err := ValidatePublicURL(context.Background(), "https://rebind.example.com/"); err == nil {
		t.Error("a name resolving to both a public and a private address was allowed")
	}
}

func TestAnUnresolvableHostIsRefused(t *testing.T) {
	// Fail closed. A name we cannot check is not a name we dial.
	withResolver(t, fakeResolver{err: errors.New("nxdomain")})
	if err := ValidatePublicURL(context.Background(), "https://nowhere.invalid/"); err == nil {
		t.Error("an unresolvable host was allowed")
	}
	withResolver(t, fakeResolver{addrs: nil})
	if err := ValidatePublicURL(context.Background(), "https://empty.invalid/"); err == nil {
		t.Error("a host resolving to nothing was allowed")
	}
}

func TestOnlyTheAllowedSchemes(t *testing.T) {
	// file:// and gopher:// are the classic ways to turn an HTTP fetcher into a file reader.
	for _, raw := range []string{
		"file:///etc/passwd",
		"gopher://127.0.0.1:11211/",
		"ftp://example.com/",
		"//example.com/",
	} {
		if err := ValidatePublicURL(context.Background(), raw); err == nil {
			t.Errorf("%s was allowed", raw)
		}
	}
}

func TestTheErrorSaysWhichSchemesAreAllowed(t *testing.T) {
	err := ValidatePublicURL(context.Background(), "file:///etc/passwd")
	if err == nil || !strings.Contains(err.Error(), "http or https") {
		t.Errorf("error = %v, want it to name the allowed schemes", err)
	}
	if !IsSsrfError(err) {
		t.Error("the caller needs to be able to recognise this as an SSRF refusal")
	}
}

func TestACallerCanWidenTheSchemes(t *testing.T) {
	// The WebSocket connector dials ws:// and wss://, which are the same guard with a different
	// scheme list rather than a second copy of the blocklist.
	withResolver(t, fakeResolver{addrs: ips("203.0.113.9")})
	if err := ValidatePublicURL(context.Background(), "wss://agent.example.com/", "ws", "wss"); err != nil {
		t.Errorf("wss should be allowed when the caller asks for it: %v", err)
	}
	if err := ValidatePublicURL(context.Background(), "wss://127.0.0.1/", "ws", "wss"); err == nil {
		t.Error("widening the scheme must not widen the address blocklist")
	}
}

func TestAMalformedURLIsRefused(t *testing.T) {
	for _, raw := range []string{"", "http://", "not a url at all", "http:// spaces"} {
		if err := ValidatePublicURL(context.Background(), raw); err == nil {
			t.Errorf("%q was allowed", raw)
		}
	}
}

func TestTheBlocklistParsed(t *testing.T) {
	// The blocklist is built at init from string CIDRs. If one were malformed it would panic — but
	// a future edit that drops an entry would not, so this pins the count.
	if len(blockedNets) != 11 {
		t.Errorf("blocklist has %d entries, want 11 — was one removed?", len(blockedNets))
	}
}

// TestTheFourClosedGaps names each range that used to be reachable, one case per CIDR, because a
// table with a hole in it looks exactly like one without.
func TestTheFourClosedGaps(t *testing.T) {
	for _, c := range []struct {
		raw  string
		what string
	}{
		{"http://0.0.0.0:8080/", "0.0.0.0/8 — the shortest way to spell loopback without writing 127"},
		{"http://0.0.0.1/", "0.0.0.0/8, upper half"},
		{"http://[::]/", "::/128 — the IPv6 unspecified address"},
		{"http://[fe80::1]/", "fe80::/10 — IPv6 link-local, where metadata answers on dual-stack"},
		{"http://[fe80::a00:27ff:fe4e:66a1]/", "fe80::/10, a real SLAAC address"},
		{"http://100.64.0.1/", "100.64.0.0/10 — CGNAT, the cloud node network"},
		{"http://100.127.255.254/", "100.64.0.0/10, upper edge"},
	} {
		if err := ValidatePublicURL(context.Background(), c.raw); err == nil {
			t.Errorf("%s was allowed (%s)", c.raw, c.what)
		}
	}
}

// TestTheClosedGapsDidNotSwallowNeighbouringPublicSpace — 100.64.0.0/10 sits between two public /8s
// and fe80::/10 between two routable ranges, so a mask off by a bit blocks real customer traffic.
func TestTheClosedGapsDidNotSwallowNeighbouringPublicSpace(t *testing.T) {
	for _, ip := range []string{"100.63.255.255", "100.128.0.1", "1.2.3.4", "2001:db8::1", "fec0::1"} {
		withResolver(t, fakeResolver{addrs: ips(ip)})
		if err := ValidatePublicURL(context.Background(), "https://agent.example.com/"); err != nil {
			t.Errorf("%s is public space and was refused: %v", ip, err)
		}
	}
}

func TestValidateScheme(t *testing.T) {
	for _, tc := range []struct {
		url     string
		schemes []string
		wantErr bool
	}{
		{"http://127.0.0.1:8080/chat", nil, false},
		{"https://10.0.0.1/chat", nil, false},
		{"wss://localhost:8080/ws", []string{"ws", "wss"}, false},
		{"ftp://example.com/", nil, true},
		{"file:///etc/passwd", nil, true},
		{"not-a-url", nil, true},
		{"http://", nil, true},
	} {
		err := ValidateScheme(tc.url, tc.schemes...)
		if (err != nil) != tc.wantErr {
			t.Errorf("ValidateScheme(%q, %v) err = %v, wantErr = %v", tc.url, tc.schemes, err, tc.wantErr)
		}
	}
}
