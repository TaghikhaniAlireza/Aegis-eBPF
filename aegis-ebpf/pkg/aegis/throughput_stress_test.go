package aegis_test

import (
	"testing"
	"time"

	"github.com/aegis-ebpf/sdk/pkg/aegis"
)

// TestHighThroughputJitStorm runs Rust's scoped JIT-storm simulator (100k events) and asserts
// all events are accounted for (no silent loss). Throughput is logged for CI / local profiling.
func TestHighThroughputJitStorm(t *testing.T) {
	const count uint32 = 100_000

	a, err := aegis.NewArena(65536)
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()

	stats, elapsed, err := a.SimulateJitStormDuration(count)
	if err != nil {
		t.Fatalf("SimulateJitStorm: %v", err)
	}
	if stats.Requested != uint64(count) {
		t.Fatalf("requested: want %d got %d", count, stats.Requested)
	}
	if stats.Pushed != stats.Popped || stats.Pushed != stats.Requested {
		t.Fatalf("mismatch pushed=%d popped=%d requested=%d full_retries=%d",
			stats.Pushed, stats.Popped, stats.Requested, stats.FullRetries)
	}

	sec := elapsed.Seconds()
	if sec <= 0 {
		sec = 1e-9
	}
	eps := float64(stats.Popped) / sec
	t.Logf("jit_storm: %d events in %v (%.0f events/s), full_retries=%d",
		stats.Popped, elapsed, eps, stats.FullRetries)

	// Sanity bound: 100k ring ops should complete quickly on CI hardware (tunable if flaky).
	if elapsed > 30*time.Second {
		t.Fatalf("storm took too long: %v", elapsed)
	}
}

// TestHighThroughputConcurrentDrain exercises the same arena from Go while a background goroutine
// drains (optional extra contention on top of the Rust-only storm path).
func TestHighThroughputConcurrentDrain(t *testing.T) {
	const count uint32 = 50_000

	a, err := aegis.NewArena(32768)
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()

	done := make(chan struct{})
	go func() {
		for {
			select {
			case <-done:
				return
			default:
			}
			_, _ = a.TryPop()
		}
	}()

	stats, elapsed, err := a.SimulateJitStormDuration(count)
	close(done)

	if err != nil {
		t.Fatalf("SimulateJitStorm: %v", err)
	}
	if stats.Pushed != stats.Requested || stats.Popped != stats.Requested {
		t.Fatalf("counts pushed=%d popped=%d requested=%d", stats.Pushed, stats.Popped, stats.Requested)
	}
	t.Logf("concurrent_drain storm: %v, full_retries=%d", elapsed, stats.FullRetries)
}
