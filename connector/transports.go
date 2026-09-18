// Copyright 2026 Radoslaw Brus. SPDX-License-Identifier: Apache-2.0

package connector

// The transport catalogue: which transports a scan may speak, and how each is spelled for a reader.
//
// The one thing this file gets right, or the rest does not matter: there is ONE list. It exists
// because there were two, and in production they disagreed — a transport was added and its count
// updated in one place, while a second, hardcoded copy behind an API kept answering the old number.
// The build was green and the binary was correct; the surface people actually read was stale.
//
// A count that two places compute independently is a count that will eventually disagree, and the
// one people see is rarely the one that gets updated. Adding a transport is now a row here.
type Transport struct {
	// ID is the value a scan config and the CLI --transport flag carry.
	ID string
	// Display is the spelling a human-facing surface uses.
	Display string
}

// Transports is every transport the engine can drive, in the order surfaces list them.
//
// `browser` is last and named "Web chat" rather than "Browser" on purpose: the buyer recognises the
// thing being scanned (a chat widget on a page), not the mechanism used to reach it.
var Transports = []Transport{
	{ID: "rest", Display: "REST"},
	{ID: "mcp", Display: "MCP"},
	{ID: "a2a", Display: "A2A"},
	{ID: "ws", Display: "WebSocket"},
	{ID: "browser", Display: "Web chat"},
}

// TransportIDs is the set a scan may use, for gating a request.
func TransportIDs() map[string]bool {
	out := make(map[string]bool, len(Transports))
	for _, t := range Transports {
		out[t.ID] = true
	}
	return out
}

// TransportDisplayNames is the list a catalogue endpoint or a marketing surface prints.
func TransportDisplayNames() []string {
	out := make([]string, 0, len(Transports))
	for _, t := range Transports {
		out = append(out, t.Display)
	}
	return out
}
