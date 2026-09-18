// Copyright 2026 Radoslaw Brus. SPDX-License-Identifier: Apache-2.0

// Package pyjson writes JSON the way Python's json.dumps does.
//
// Python's default separators are ", " and ": ", Go's encoder is compact, and both are valid JSON —
// which is exactly why this keeps mattering. Wherever a Go value has to land on the same BYTES a
// Python value would, the difference is a failing differential test at best and a corrupt record at
// worst: the store keeps several fields as JSON STRINGS, so the spacing is part of the stored value
// rather than an encoding detail.
//
// This lived in the A2A connector first. It is here because the scan store needed it too, and a
// second copy of a byte-exactness rule is the kind of thing that drifts silently and is then very
// hard to explain.
package pyjson

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"
	"unicode/utf8"
)

// Dumps marshals a value with Python's spacing. Note that Go sorts map keys while Python preserves
// insertion order — for a map there is no ordering either language can promise the other, so use
// FromRaw when the key order of an existing document has to survive.
func Dumps(v any) (string, error) {
	raw, err := json.Marshal(v)
	if err != nil {
		return "", err
	}
	return SpaceSeparators(string(raw)), nil
}

// FromRaw re-spaces bytes that are already JSON, preserving their key order. json.Compact strips
// insignificant whitespace at the byte level rather than re-encoding, so an indented document and a
// compact one both land on the single form Python would print.
func FromRaw(raw json.RawMessage) string {
	var compact bytes.Buffer
	if json.Compact(&compact, raw) != nil {
		return SpaceSeparators(string(raw))
	}
	return SpaceSeparators(compact.String())
}

// SpaceSeparators inserts the ", " and ": " spacing json.dumps uses, without re-parsing — it walks
// the bytes and skips anything inside a string literal, so a comma or colon in a value is left
// alone.
func SpaceSeparators(s string) string {
	var b strings.Builder
	b.Grow(len(s) + len(s)/8)
	inStr := false
	escaped := false
	for i := 0; i < len(s); i++ {
		c := s[i]
		b.WriteByte(c)
		if escaped {
			escaped = false
			continue
		}
		switch c {
		case '\\':
			if inStr {
				escaped = true
			}
		case '"':
			inStr = !inStr
		case ',', ':':
			if !inStr {
				b.WriteByte(' ')
			}
		}
	}
	return b.String()
}

// EnsureASCII escapes every non-ASCII rune to \uXXXX, which is what json.dumps does by default.
//
// This is not cosmetic here. Unicode smuggling is a whole technique family in this product —
// zero-width joiners, RTL overrides, homoglyphs and combining marks ARE the payload — so a stored
// attack record is full of characters that Python escapes and Go's encoder emits raw. The two
// encodings carry the same value but differ in LENGTH, sometimes by a factor of three, and length is
// what a Firestore field cap measures.
//
// Astral characters become surrogate pairs, matching Python: json.dumps writes an emoji as
// 😀 rather than \U0001f600.
//
// Safe to run over a whole JSON document: in valid JSON a non-ASCII byte can only occur inside a
// string literal.
func EnsureASCII(s string) string {
	if isASCII(s) {
		return s
	}
	var b strings.Builder
	b.Grow(len(s) + len(s)/2)
	for _, r := range s {
		switch {
		case r < utf8.RuneSelf:
			b.WriteByte(byte(r))
		case r > 0xFFFF:
			r -= 0x10000
			fmt.Fprintf(&b, "\\u%04x\\u%04x", 0xD800+(r>>10), 0xDC00+(r&0x3FF))
		default:
			fmt.Fprintf(&b, "\\u%04x", r)
		}
	}
	return b.String()
}

func isASCII(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] >= utf8.RuneSelf {
			return false
		}
	}
	return true
}

// Marshal encodes a value the way Python's json.dumps would: no HTML escaping, non-ASCII escaped,
// and Python's ", " / ": " separators.
//
// Go's encoder escapes <, > and & to < and friends so a blob can be embedded in HTML without
// further thought. Python does not, and a prompt-injection payload is mostly angle brackets — so the
// same record round-trips to a different length in each language unless this is turned off.
//
// Key ORDER still differs: Go sorts, Python preserves insertion order. Nothing either language can
// do about that, so a caller needing byte-identical output must control ordering itself.
func Marshal(v any) (string, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return "", err
	}
	// Encode appends a newline that Marshal does not.
	return EnsureASCII(SpaceSeparators(strings.TrimRight(buf.String(), "\n"))), nil
}
