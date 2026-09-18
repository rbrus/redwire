// Copyright 2026 Radoslaw Brus. SPDX-License-Identifier: Apache-2.0

// Python and Go both emit valid JSON and disagree on the bytes. These pin the difference, because
// the scan store keeps several fields as JSON STRINGS — there, the spacing IS the stored value.
package pyjson

import (
	"encoding/json"
	"testing"
)

func TestSpacingMatchesJSONDumps(t *testing.T) {
	if got := SpaceSeparators(`{"state":"completed","code":7}`); got != `{"state": "completed", "code": 7}` {
		t.Errorf("spacing = %q", got)
	}
}

func TestSeparatorsInsideStringsAreLeftAlone(t *testing.T) {
	// The reason this walks bytes rather than splitting on commas.
	for _, c := range []struct{ in, want string }{
		{`{"msg":"a,b:c"}`, `{"msg": "a,b:c"}`},
		{`{"msg":"quote\" ,inside"}`, `{"msg": "quote\" ,inside"}`},
		{`{"msg":"trailing backslash\\","n":1}`, `{"msg": "trailing backslash\\", "n": 1}`},
	} {
		if got := SpaceSeparators(c.in); got != c.want {
			t.Errorf("SpaceSeparators(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestFromRawPreservesKeyOrder(t *testing.T) {
	// The whole reason FromRaw exists: a Go map would sort these, and the wire order is what Python
	// would have printed.
	raw := json.RawMessage(`{"zebra":1,"apple":2}`)
	if got := FromRaw(raw); got != `{"zebra": 1, "apple": 2}` {
		t.Errorf("FromRaw = %q, want the wire order preserved", got)
	}
}

func TestFromRawNormalisesIndentedInput(t *testing.T) {
	raw := json.RawMessage("{\n  \"a\" : 1,\n  \"b\":2\n}")
	if got := FromRaw(raw); got != `{"a": 1, "b": 2}` {
		t.Errorf("FromRaw = %q", got)
	}
}

func TestDumpsRoundTrips(t *testing.T) {
	got, err := Dumps(map[string]any{"a": 1})
	if err != nil || got != `{"a": 1}` {
		t.Errorf("Dumps = %q, %v", got, err)
	}
}
