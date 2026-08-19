package memory_test

import (
	"testing"

	"github.com/deepteams/credbound"
	"github.com/deepteams/credbound/internal/storetest"
	"github.com/deepteams/credbound/memory"
)

// TestConformance runs the shared store conformance suite against the
// in-memory store, which is the reference implementation the SQL stores must
// agree with.
func TestConformance(t *testing.T) {
	storetest.Run(t, storetest.Factory{
		Name: "memory",
		New:  func(*testing.T) credbound.Store { return memory.New() },
	})
}
