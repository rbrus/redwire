// Package redwire reaches an AI agent behind any of five transports through one interface.
//
// A red-team's payload does not care whether the agent answers over REST, MCP, A2A, a WebSocket, or
// a chat widget in a browser. Target is that indifference made concrete: every connector in this
// module satisfies it, so an attack is written once against Send and runs against all five.
package redwire

import "context"

// Target is anything a message can be sent to. Each connector in ./connector satisfies it — the
// engine above them depends on this behaviour, never on the transport underneath.
type Target interface {
	// Send delivers one message to the agent and returns its reply. A transport-level failure — the
	// endpoint unreachable, auth rejected — is an error; a target that answers, even to refuse, is a
	// reply. The distinction is the whole point: a refusal is evidence, not a failure.
	Send(ctx context.Context, message string) (string, error)
}
