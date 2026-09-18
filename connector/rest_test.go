// Copyright 2026 Radoslaw Brus. SPDX-License-Identifier: Apache-2.0

// Behavioural tests for the REST transport.
//
// These pin the status-code policy that is easy to "fix" wrongly: when red-teaming, a target's 4xx
// is usually the RESULT — a content filter firing is exactly what we came to observe — so it must be
// captured as text, not raised. Only 401/403 stops a scan. Nested- and list-path resolution is
// covered in rest_mapping_test.go.
package connector

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func newTestConnector(endpoint string) *REST {
	return NewREST(Config{
		Endpoint:        endpoint,
		Auth:            Auth{Type: AuthBearer, Token: "t0ken"},
		RequestMapping:  Mapping{MessageField: "input.text"},
		ResponseMapping: Mapping{MessageField: "choices[0].message.content"},
	}, loopbackClient())
}

func TestItSendsThePayloadWhereTheConfigSaysAndReadsTheAnswerBack(t *testing.T) {
	var seenBody map[string]any
	var seenAuth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seenAuth = r.Header.Get("Authorization")
		_ = json.NewDecoder(r.Body).Decode(&seenBody)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"choices":[{"message":{"content":"the answer"}}]}`))
	}))
	defer srv.Close()

	got, err := newTestConnector(srv.URL).Send(context.Background(), "attack payload")
	if err != nil {
		t.Fatalf("send: %v", err)
	}
	if got != "the answer" {
		t.Errorf("response = %q, want %q", got, "the answer")
	}
	if seenAuth != "Bearer t0ken" {
		t.Errorf("auth header = %q", seenAuth)
	}
	inner, _ := seenBody["input"].(map[string]any)
	if inner["text"] != "attack payload" {
		t.Errorf("payload landed at the wrong path: %v", seenBody)
	}
}

func TestATargetRejectionIsEvidenceNotAnError(t *testing.T) {
	// The case that matters: a guardrail refusing us with 400 is a successful observation.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte("content filter triggered"))
	}))
	defer srv.Close()

	got, err := newTestConnector(srv.URL).Send(context.Background(), "x")
	if err != nil {
		t.Fatalf("a 400 must not abort the scan, got error: %v", err)
	}
	if got != "[TARGET REJECTED 400] content filter triggered" {
		t.Errorf("got %q", got)
	}
}

func TestAServerErrorPrefersTheStructuredMessage(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(`{"error":{"message":"upstream model timeout"}}`))
	}))
	defer srv.Close()

	// A 5xx is an ERROR, not the agent's words: it used to come back as "[TARGET ERROR 500] …" with a
	// nil error, so the attempt carried no engine.Attempt.Error and counted as a technique the target
	// executed. The structured-message preference this test was written for survives — it is what the
	// error says.
	got, err := newTestConnector(srv.URL).Send(context.Background(), "x")
	if err == nil {
		t.Fatalf("a 500 was returned as the target's answer: %q", got)
	}
	if got != "" {
		t.Errorf("an errored send must return no answer, got %q", got)
	}
	if !strings.Contains(err.Error(), "upstream model timeout") {
		t.Errorf("the structured message was dropped: %v", err)
	}
}

func TestOnlyAuthFailureStopsTheScan(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	defer srv.Close()

	_, err := newTestConnector(srv.URL).Send(context.Background(), "x")
	if err == nil {
		t.Fatal("403 must be an error — we cannot reach the target as ourselves")
	}
	var authErr *AuthError
	if !asAuthError(err, &authErr) || authErr.StatusCode != http.StatusForbidden {
		t.Errorf("want AuthError{403}, got %v", err)
	}
}

// TestANonJSONBodyIsAnAnswerOnlyWhenNoFieldWasNamed splits a case that used to be one.
//
// A plain-text agent is legitimate and its body IS the answer. But a target configured to reply in a
// JSON field and replying with HTML did not answer in the shape it was declared to answer in — and the
// case that matters is not a plain-text agent, it is a sign-in interstitial served 200 OK, whose login
// page became the agent's own words for every technique in a scan while nothing in the status said
// anything was wrong.
func TestANonJSONBodyIsAnAnswerOnlyWhenNoFieldWasNamed(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("plain text reply"))
	}))
	defer srv.Close()

	// No response field named: the body is the answer.
	plain := NewREST(Config{
		Endpoint: srv.URL, Auth: Auth{Type: AuthNone},
		RequestMapping: Mapping{MessageField: "input.text"},
	}, loopbackClient())
	got, err := plain.Send(context.Background(), "x")
	if err != nil {
		t.Fatalf("a plain-text agent must still answer: %v", err)
	}
	if got != "plain text reply" {
		t.Errorf("got %q", got)
	}

	// A field WAS named and the body is not JSON: that is a contract failure, not an answer.
	interstitial := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("<html><body><h1>Authentication required</h1></body></html>"))
	}))
	defer interstitial.Close()
	if out, err := newTestConnector(interstitial.URL).Send(context.Background(), "x"); err == nil {
		t.Errorf("a sign-in page served 200 OK was accepted as the agent's answer: %q", out)
	}
}

func asAuthError(err error, target **AuthError) bool {
	e, ok := err.(*AuthError)
	if ok {
		*target = e
	}
	return ok
}
