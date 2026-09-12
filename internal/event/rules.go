package event

import (
	"fmt"
	"strings"
)

// Severity orders alerts from background noise to "wake somebody up".
type Severity int

const (
	SevInfo Severity = iota
	SevLow
	SevMedium
	SevHigh
	SevCritical
)

var severityNames = map[Severity]string{
	SevInfo:     "info",
	SevLow:      "low",
	SevMedium:   "medium",
	SevHigh:     "high",
	SevCritical: "critical",
}

func (s Severity) String() string {
	if name, ok := severityNames[s]; ok {
		return name
	}
	return "unknown"
}

// ParseSeverity accepts the lowercase names emitted by String.
func ParseSeverity(s string) (Severity, error) {
	for sev, name := range severityNames {
		if strings.EqualFold(s, name) {
			return sev, nil
		}
	}
	return SevInfo, fmt.Errorf("unknown severity %q (want info, low, medium, high or critical)", s)
}

// Signal identifies which kernel-side probe produced an event. Values are
// shared with bpf/wraith.h and must not be renumbered.
type Signal uint32

const (
	SignalFilelessExec  Signal = 1
	SignalPreloadHijack Signal = 2
	SignalProcMemWrite  Signal = 3
	SignalPtraceInject  Signal = 4
	SignalTmpfsExec     Signal = 5
	SignalMemfdCreate   Signal = 6
)

// Rule is the analyst-facing description of a detection.
type Rule struct {
	Signal        Signal
	ID            string
	Title         string
	Severity      Severity
	Technique     string
	TechniqueName string
	Rationale     string
}

var ruleCatalog = []Rule{
	{
		Signal:        SignalFilelessExec,
		ID:            "fileless_exec",
		Title:         "Execution of an in-memory image",
		Severity:      SevCritical,
		Technique:     "T1620",
		TechniqueName: "Reflective Code Loading",
		Rationale: "The executed image never existed as a file on disk. It came from a memfd or a " +
			"file descriptor. Legitimate software almost never does this; droppers and packed " +
			"ELF loaders do it to keep the payload off the filesystem.",
	},
	{
		Signal:        SignalPreloadHijack,
		ID:            "preload_hijack",
		Title:         "Dynamic loader hijack via LD_PRELOAD/LD_AUDIT",
		Severity:      SevHigh,
		Technique:     "T1574.006",
		TechniqueName: "Hijack Execution Flow: Dynamic Linker Hijacking",
		Rationale: "A process was launched with an attacker-controllable shared object forced into " +
			"its address space, the standard userland way to hook libc calls and hide files, " +
			"processes or network connections.",
	},
	{
		Signal:        SignalProcMemWrite,
		ID:            "proc_mem_write",
		Title:         "Cross-process memory write",
		Severity:      SevCritical,
		Technique:     "T1055.009",
		TechniqueName: "Process Injection: Proc Memory",
		Rationale: "One process wrote directly into another's address space via process_vm_writev. " +
			"Outside of debuggers and checkpoint tooling this is code injection.",
	},
	{
		Signal:        SignalPtraceInject,
		ID:            "ptrace_inject",
		Title:         "Memory-modifying ptrace request",
		Severity:      SevHigh,
		Technique:     "T1055.008",
		TechniqueName: "Process Injection: Ptrace System Calls",
		Rationale: "A process attached to another and issued a request that mutates its memory or " +
			"registers: the ptrace half of Linux process injection.",
	},
	{
		Signal:        SignalTmpfsExec,
		ID:            "tmpfs_exec",
		Title:         "Execution from a world-writable path",
		Severity:      SevMedium,
		Technique:     "T1036",
		TechniqueName: "Masquerading",
		Rationale: "The binary was executed out of /tmp, /var/tmp or shared memory. Common in " +
			"post-exploitation staging, rare in packaged software.",
	},
	{
		Signal:        SignalMemfdCreate,
		ID:            "memfd_create",
		Title:         "Anonymous in-memory file created",
		Severity:      SevInfo,
		Technique:     "T1620",
		TechniqueName: "Reflective Code Loading",
		Rationale: "Context for fileless execution: on its own memfd_create is used by legitimate " +
			"runtimes too, so it is only reported when info signals are enabled.",
	},
}

var rulesBySignal = func() map[Signal]Rule {
	m := make(map[Signal]Rule, len(ruleCatalog))
	for _, r := range ruleCatalog {
		m[r.Signal] = r
	}
	return m
}()

// Rules returns the detection catalog in declaration order.
func Rules() []Rule {
	out := make([]Rule, len(ruleCatalog))
	copy(out, ruleCatalog)
	return out
}

// Lookup resolves the rule a kernel signal belongs to.
func Lookup(s Signal) (Rule, bool) {
	r, ok := rulesBySignal[s]
	return r, ok
}

// ptraceRequests covers the requests the kernel-side filter lets through.
var ptraceRequests = map[uint64]string{
	4:      "PTRACE_POKETEXT",
	5:      "PTRACE_POKEDATA",
	6:      "PTRACE_POKEUSR",
	13:     "PTRACE_SETREGS",
	15:     "PTRACE_SETFPREGS",
	16:     "PTRACE_ATTACH",
	0x4205: "PTRACE_SETREGSET",
	0x4206: "PTRACE_SEIZE",
}

// PtraceRequestName renders a ptrace request constant for humans.
func PtraceRequestName(req uint64) string {
	if name, ok := ptraceRequests[req]; ok {
		return name
	}
	return fmt.Sprintf("request %d", req)
}
