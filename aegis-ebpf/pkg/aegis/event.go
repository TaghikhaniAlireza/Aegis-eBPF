package aegis

/*
#include "aegis.h"
*/
import "C"

// Syscall identifiers matching the Rust/kernel bridge (MemorySyscall).
const (
	SyscallMmap        uint32 = 1
	SyscallMprotect    uint32 = 2
	SyscallMemfdCreate uint32 = 3
	SyscallPtrace      uint32 = 4
)

// Event mirrors C.RawMemoryEvent / the Rust FFI layout (96 bytes).
type Event struct {
	TimestampNs uint64
	TGID        uint32
	PID         uint32
	SyscallID   uint32
	Args        [6]uint64
	CgroupID    uint64
	Comm        [16]byte
}

// CommString returns the command name as a NUL-terminated Go string.
func (e *Event) CommString() string {
	n := 0
	for n < len(e.Comm) && e.Comm[n] != 0 {
		n++
	}
	return string(e.Comm[:n])
}

func fromCEvent(ce *C.RawMemoryEvent) Event {
	var args [6]uint64
	for i := range args {
		args[i] = uint64(ce.args[i])
	}
	var comm [16]byte
	for i := 0; i < 16; i++ {
		comm[i] = byte(ce.comm[i])
	}
	return Event{
		TimestampNs: uint64(ce.timestamp_ns),
		TGID:        uint32(ce.tgid),
		PID:         uint32(ce.pid),
		SyscallID:   uint32(ce.syscall_id),
		Args:        args,
		CgroupID:    uint64(ce.cgroup_id),
		Comm:        comm,
	}
}

func (e *Event) toCEvent() C.RawMemoryEvent {
	var ce C.RawMemoryEvent
	ce.timestamp_ns = C.uint64_t(e.TimestampNs)
	ce.tgid = C.uint32_t(e.TGID)
	ce.pid = C.uint32_t(e.PID)
	ce.syscall_id = C.uint32_t(e.SyscallID)
	ce._pad0 = 0
	for i := range e.Args {
		ce.args[i] = C.uint64_t(e.Args[i])
	}
	ce.cgroup_id = C.uint64_t(e.CgroupID)
	for i := 0; i < 16; i++ {
		ce.comm[i] = C.uint8_t(e.Comm[i])
	}
	return ce
}
