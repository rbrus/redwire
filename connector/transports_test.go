// SPDX-License-Identifier: Apache-2.0

package connector

import (
	"reflect"
	"testing"
)

func TestTransportsCatalogue(t *testing.T) {
	if len(Transports) != 5 {
		t.Fatalf("expected 5 transports, got %d", len(Transports))
	}

	ids := TransportIDs()
	wantIDs := map[string]bool{
		"rest":    true,
		"mcp":     true,
		"a2a":     true,
		"ws":      true,
		"browser": true,
	}
	if !reflect.DeepEqual(ids, wantIDs) {
		t.Errorf("TransportIDs() = %v, want %v", ids, wantIDs)
	}

	displayNames := TransportDisplayNames()
	wantDisplay := []string{"REST", "MCP", "A2A", "WebSocket", "Web chat"}
	if !reflect.DeepEqual(displayNames, wantDisplay) {
		t.Errorf("TransportDisplayNames() = %v, want %v", displayNames, wantDisplay)
	}
}
