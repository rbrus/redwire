// Copyright 2026 Radoslaw Brus. SPDX-License-Identifier: Apache-2.0

// Package ssrf is the guard on every outbound URL a caller supplies.
//
// One blocklist and one resolution rule, shared by everything that dials a caller-supplied endpoint:
// the quick-probe endpoint, every scan-target connector, and any future connector that navigates to
// an arbitrary URL. A second copy of a blocklist is a second thing to forget to update, and the one
// that gets forgotten is the one an attacker finds.
package ssrf

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/url"
	"strings"
)

// Error is a URL that targets internal infrastructure, will not resolve, or uses a scheme we do not
// dial. Callers translate it into their own type — the API answers 422, a connector wraps it.
type Error struct{ Reason string }

func (e *Error) Error() string { return e.Reason }

func fail(reason string) error { return &Error{Reason: reason} }

// blockedNets are RFC 1918 private ranges, loopback, link-local (which includes the cloud metadata
// range at 169.254.169.254), and IPv6 unique-local and loopback. A client that resolves to any of
// these is almost certainly being pointed at internal infrastructure.
//
// The last four close holes rather than add breadth, and each is a real route to the same place:
// 0.0.0.0/8 because "0.0.0.0" and "0.0.0.1" reach the local host on Linux and are the cheapest way
// to spell loopback without writing 127; ::/128 for the same reason over IPv6; fe80::/10 because
// IPv6 link-local is where the metadata service answers on a dual-stack instance and blocking only
// 169.254.0.0/16 leaves that half open; and 100.64.0.0/10 (CGNAT, RFC 6598) because that is the
// range cloud providers hand to the node network — on GKE and EKS it addresses the other tenants'
// pods.
var blockedNets = func() []*net.IPNet {
	cidrs := []string{
		"127.0.0.0/8",
		"10.0.0.0/8",
		"172.16.0.0/12",
		"192.168.0.0/16",
		"169.254.0.0/16",
		"0.0.0.0/8",
		"100.64.0.0/10",
		"::1/128",
		"::/128",
		"fc00::/7",
		"fe80::/10",
	}
	out := make([]*net.IPNet, 0, len(cidrs))
	for _, c := range cidrs {
		_, n, err := net.ParseCIDR(c)
		if err != nil {
			// A malformed constant here would silently shrink the blocklist, which is the one
			// failure mode this guard cannot have.
			panic("ssrf: bad blocklist CIDR " + c)
		}
		out = append(out, n)
	}
	return out
}()

// blockedHosts are names that reach internal infrastructure without needing a private IP.
var blockedHosts = map[string]bool{
	"localhost":                true,
	"localhost.localdomain":    true,
	"metadata.google.internal": true,
}

func checkIP(ip net.IP) error {
	for _, n := range blockedNets {
		if n.Contains(ip) {
			return fail("Private/internal addresses are not allowed.")
		}
	}
	return nil
}

// Resolver looks a hostname up. Injectable so a test can drive the rebinding case without DNS.
type Resolver interface {
	LookupIPAddr(ctx context.Context, host string) ([]net.IPAddr, error)
}

// DefaultResolver is the system resolver.
var DefaultResolver Resolver = net.DefaultResolver

// ValidatePublicURL rejects a URL that resolves to internal infrastructure.
//
// A domain name is RESOLVED and every returned address checked, which closes the DNS-rebinding
// window at validation time: an attacker who answers with a public IP now and rebinds to an internal
// one later still fails here.
//
// Note what this does NOT do, and where the rest of it lives. It validates; it does not pin the
// resolved address for the connection that follows, and it says nothing about where a redirect
// leads. Between this call and the dial the name can answer differently, and a 302 skips the check
// entirely. Both halves are closed by NewHTTPClient (client.go) — use it for anything that dials a
// caller-supplied endpoint, because this function alone is a check, not a guard.
func ValidatePublicURL(ctx context.Context, raw string, allowedSchemes ...string) error {
	if len(allowedSchemes) == 0 {
		allowedSchemes = []string{"http", "https"}
	}
	parsed, err := url.Parse(raw)
	if err != nil {
		return fail("Invalid endpoint URL.")
	}
	if !contains(allowedSchemes, parsed.Scheme) {
		return fail(fmt.Sprintf("Endpoint must use %s.", strings.Join(allowedSchemes, " or ")))
	}
	host := parsed.Hostname()
	if host == "" {
		return fail("Invalid endpoint URL.")
	}

	// A literal address is checked directly; there is nothing to resolve and no rebinding window.
	if ip := net.ParseIP(host); ip != nil {
		return checkIP(ip)
	}

	if blockedHosts[strings.ToLower(host)] {
		return fail("This hostname is not allowed.")
	}
	addrs, err := DefaultResolver.LookupIPAddr(ctx, host)
	if err != nil || len(addrs) == 0 {
		return fail("Could not resolve hostname.")
	}
	// EVERY address, not the first. A name that answers with one public and one private address is
	// the attack, not an accident.
	for _, a := range addrs {
		if err := checkIP(a.IP); err != nil {
			return err
		}
	}
	return nil
}

// ValidateScheme checks only that the URL parses and uses an allowed scheme — the sliver of
// ValidatePublicURL that survives when a caller deliberately opts into reaching their own
// private/internal targets. The address checks that block loopback, RFC-1918 and the cloud-metadata
// range are exactly what they are turning off; a valid scheme is not, so a garbage URL still fails.
// It is never reached on the path where the endpoint is an untrusted, stranger-supplied string.
func ValidateScheme(raw string, allowedSchemes ...string) error {
	if len(allowedSchemes) == 0 {
		allowedSchemes = []string{"http", "https"}
	}
	parsed, err := url.Parse(raw)
	if err != nil {
		return fail("Invalid endpoint URL.")
	}
	if !contains(allowedSchemes, parsed.Scheme) {
		return fail(fmt.Sprintf("Endpoint must use %s.", strings.Join(allowedSchemes, " or ")))
	}
	if parsed.Hostname() == "" {
		return fail("Invalid endpoint URL.")
	}
	return nil
}

func contains(list []string, want string) bool {
	for _, s := range list {
		if s == want {
			return true
		}
	}
	return false
}

// IsSsrfError reports whether an error came from this guard.
func IsSsrfError(err error) bool {
	var e *Error
	return errors.As(err, &e)
}
