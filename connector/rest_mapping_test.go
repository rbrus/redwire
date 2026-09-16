package connector

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// A 200 whose body does not contain the field we were told to read.
//
// This is the same defect the two branches above it in rest.go already guard — a target that did not
// answer in the shape it was declared to answer in — in the one case nobody covered. It was found by
// pointing a real dashboard scan at an agent replying `{"reply": ...}` while the API path defaults to
// `response`: 35 attempts, every extracted response empty, and a report that said "No vulnerabilities
// were found... Overall risk: Low."
//
// Nothing errored, so delivered-vs-dispatched was satisfied and every honesty check downstream passed
// on evidence that did not exist. The distinction that matters is ABSENT versus EMPTY: a missing field
// is a broken mapping and cannot be judged, while a field that is present and empty is the agent's
// own answer, however odd, and must still be scored.

func restAgainst(t *testing.T, handler http.HandlerFunc, replyField string) (*REST, func()) {
	t.Helper()
	srv := httptest.NewServer(handler)
	c := NewREST(Config{
		Endpoint:        srv.URL,
		RequestMapping:  Mapping{MessageField: "message"},
		ResponseMapping: Mapping{MessageField: replyField},
		Timeout:         5 * time.Second,
	}, srv.Client())
	return c, srv.Close
}

func jsonHandler(body string) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(body))
	}
}

func TestAMissingReplyFieldIsAnErrorNotAnEmptyAnswer(t *testing.T) {
	c, done := restAgainst(t, jsonHandler(`{"reply":"I can't help with that."}`), "response")
	defer done()

	got, err := c.Send(context.Background(), "hello")
	if err == nil {
		t.Fatalf("no error for a body with no %q field; got %q. An unreadable reply scored as an "+
			"empty answer is how a scan reports a target clean without ever reading it", "response", got)
	}
	// The message has to be actionable: an operator seeing this must be able to fix the mapping
	// without opening a debugger, so it names what was expected AND what was actually there.
	for _, want := range []string{"response", "reply"} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("error does not mention %q, so it cannot be acted on: %v", want, err)
		}
	}
}

func TestAPresentButEmptyReplyIsStillTheAgentsAnswer(t *testing.T) {
	// The other half, and the reason this is not simply "empty means broken". An agent that answers
	// with an empty string HAS answered; turning that into a transport error would discard a real
	// result and would be the mirror image of the bug being fixed.
	c, done := restAgainst(t, jsonHandler(`{"response":""}`), "response")
	defer done()

	got, err := c.Send(context.Background(), "hello")
	if err != nil {
		t.Fatalf("a present-but-empty field must be an answer, not an error: %v", err)
	}
	if got != "" {
		t.Fatalf("got %q, want the empty answer", got)
	}
}

func TestNestedAndListPathsStillResolve(t *testing.T) {
	for _, tc := range []struct{ name, body, path, want string }{
		{"nested object", `{"data":{"text":"hi"}}`, "data.text", "hi"},
		{"list index", `{"choices":[{"message":"hi"}]}`, "choices[0].message", "hi"},
		{"non-string value", `{"response":42}`, "response", "42"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c, done := restAgainst(t, jsonHandler(tc.body), tc.path)
			defer done()
			got, err := c.Send(context.Background(), "hello")
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tc.want {
				t.Fatalf("got %q, want %q", got, tc.want)
			}
		})
	}
}

func TestAMissingNestedPathIsAlsoAnError(t *testing.T) {
	// The shallow case is the common one, but a nested path that stops resolving halfway is the same
	// broken mapping and must not come back as an empty answer either.
	for _, tc := range []struct{ name, body, path string }{
		{"missing leaf", `{"data":{"other":"hi"}}`, "data.text"},
		{"missing branch", `{"other":{"text":"hi"}}`, "data.text"},
		{"index past the end", `{"choices":[]}`, "choices[0].message"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c, done := restAgainst(t, jsonHandler(tc.body), tc.path)
			defer done()
			if got, err := c.Send(context.Background(), "hello"); err == nil {
				t.Fatalf("no error for an unresolvable path; got %q", got)
			}
		})
	}
}

func TestWithNoFieldNamedTheBodyIsTheAnswer(t *testing.T) {
	// Unchanged behaviour, pinned so the fix above cannot quietly break the operator who configured
	// no mapping at all and expects the raw body.
	c, done := restAgainst(t, jsonHandler(`{"anything":"at all"}`), "")
	defer done()
	got, err := c.Send(context.Background(), "hello")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(got, "at all") {
		t.Fatalf("got %q, want the raw body", got)
	}
}
