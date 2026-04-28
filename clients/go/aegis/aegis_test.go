package aegis

import (
	"testing"
)

// Tests require CGO and libaegis_ebpf.so (build with `cargo build -p aegis-ebpf` from repo root).

func TestSetLogLevel_allValidLevels(t *testing.T) {
	for _, lvl := range []LogLevel{
		LogLevelTrace,
		LogLevelInfo,
		LogLevelSuppressed,
		LogLevelEvent,
		LogLevelAlert,
	} {
		if err := SetLogLevel(lvl); err != nil {
			t.Fatalf("SetLogLevel(%d): %v", lvl, err)
		}
	}
}

func TestSetLogLevel_invalid(t *testing.T) {
	if err := SetLogLevel(5); err == nil {
		t.Fatal("expected error for level 5")
	}
	if err := SetLogLevel(-1); err == nil {
		t.Fatal("expected error for level -1")
	}
}

func TestInitEngineWithConfig_logLevel(t *testing.T) {
	alert := LogLevelAlert
	if err := InitEngineWithConfig(EngineConfig{LogLevel: &alert}); err != nil {
		t.Fatalf("InitEngineWithConfig: %v", err)
	}
	// Restore trace for other tests in same process if any
	_ = SetLogLevel(LogLevelTrace)
}

func TestInitEngineWithConfig_nilLogLevel(t *testing.T) {
	if err := InitEngineWithConfig(EngineConfig{}); err != nil {
		t.Fatalf("InitEngineWithConfig empty: %v", err)
	}
}

func ptrLevel(l LogLevel) *LogLevel {
	return &l
}
