package event

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// atEmptyPath mirrors AT_EMPTY_PATH, reported in Aux by the exec probes.
const atEmptyPath = 0x1000

// Process holds procfs-derived context about a pid.
type Process struct {
	PID       uint32
	Comm      string
	Exe       string
	Cmdline   string
	Container string
	// Deleted reports that the backing file of Exe is gone, either unlinked
	// after launch or never on disk to begin with.
	Deleted bool
}

func (p Process) label() string {
	switch {
	case p.Comm != "" && p.PID != 0:
		return fmt.Sprintf("%s[%d]", p.Comm, p.PID)
	case p.PID != 0:
		return fmt.Sprintf("pid %d", p.PID)
	default:
		return "unknown process"
	}
}

// Event is one detection, as delivered to the output sinks.
type Event struct {
	Time time.Time
	Rule Rule

	PID  uint32
	TID  uint32
	PPID uint32
	UID  uint32
	Comm string

	// Path is the exec target for exec-derived signals; Detail carries the
	// per-rule extra (memfd name, environment assignment).
	Path   string
	Detail string

	TargetPID uint32
	Aux       uint64

	Proc   Process
	Parent Process
	Target Process
}

// Message renders the one-line analyst-facing explanation of the alert.
func (e Event) Message() string {
	actor := Process{PID: e.PID, Comm: e.Comm}.label()

	switch e.Rule.Signal {
	case SignalFilelessExec:
		var b strings.Builder
		fmt.Fprintf(&b, "%s executed an in-memory image", actor)
		if e.Detail != "" {
			fmt.Fprintf(&b, " (memfd %q)", e.Detail)
		}
		switch {
		case e.Aux&atEmptyPath != 0:
			b.WriteString(" via execveat(AT_EMPTY_PATH)")
		case e.Path != "":
			fmt.Fprintf(&b, " via %s", e.Path)
		}
		return b.String()

	case SignalPreloadHijack:
		target := e.Path
		if target == "" {
			target = "a new process"
		}
		return fmt.Sprintf("%s launched %s with %s", actor, target, e.Detail)

	case SignalProcMemWrite:
		msg := fmt.Sprintf("%s wrote into %s via process_vm_writev", actor, e.targetLabel())
		if e.Aux > 0 {
			msg += fmt.Sprintf(" (%d remote iovec(s))", e.Aux)
		}
		return msg

	case SignalPtraceInject:
		return fmt.Sprintf("%s issued %s against %s", actor, PtraceRequestName(e.Aux), e.targetLabel())

	case SignalTmpfsExec:
		return fmt.Sprintf("%s executed %s from a world-writable path", actor, e.Path)

	case SignalMemfdCreate:
		return fmt.Sprintf("%s created anonymous in-memory file %q", actor, e.Detail)

	default:
		return fmt.Sprintf("%s triggered %s", actor, e.Rule.ID)
	}
}

func (e Event) targetLabel() string {
	if e.Target.PID != 0 || e.Target.Comm != "" {
		return e.Target.label()
	}
	return fmt.Sprintf("pid %d", e.TargetPID)
}

type jsonEvent struct {
	Time          time.Time `json:"time"`
	Rule          string    `json:"rule"`
	Severity      string    `json:"severity"`
	Technique     string    `json:"technique"`
	TechniqueName string    `json:"technique_name"`
	Message       string    `json:"message"`
	PID           uint32    `json:"pid"`
	TID           uint32    `json:"tid"`
	PPID          uint32    `json:"ppid"`
	UID           uint32    `json:"uid"`
	Comm          string    `json:"comm"`
	Exe           string    `json:"exe,omitempty"`
	ExeDeleted    bool      `json:"exe_deleted,omitempty"`
	Cmdline       string    `json:"cmdline,omitempty"`
	Container     string    `json:"container,omitempty"`
	ParentComm    string    `json:"parent_comm,omitempty"`
	ParentExe     string    `json:"parent_exe,omitempty"`
	Path          string    `json:"path,omitempty"`
	Detail        string    `json:"detail,omitempty"`
	TargetPID     uint32    `json:"target_pid,omitempty"`
	TargetComm    string    `json:"target_comm,omitempty"`
	TargetExe     string    `json:"target_exe,omitempty"`
	Aux           uint64    `json:"aux,omitempty"`
}

// MarshalJSON emits one flat object per event so the stream stays greppable
// and loads cleanly into any log pipeline.
func (e Event) MarshalJSON() ([]byte, error) {
	return json.Marshal(jsonEvent{
		Time:          e.Time.UTC(),
		Rule:          e.Rule.ID,
		Severity:      e.Rule.Severity.String(),
		Technique:     e.Rule.Technique,
		TechniqueName: e.Rule.TechniqueName,
		Message:       e.Message(),
		PID:           e.PID,
		TID:           e.TID,
		PPID:          e.PPID,
		UID:           e.UID,
		Comm:          e.Comm,
		Exe:           e.Proc.Exe,
		ExeDeleted:    e.Proc.Deleted,
		Cmdline:       e.Proc.Cmdline,
		Container:     e.Proc.Container,
		ParentComm:    e.Parent.Comm,
		ParentExe:     e.Parent.Exe,
		Path:          e.Path,
		Detail:        e.Detail,
		TargetPID:     e.TargetPID,
		TargetComm:    e.Target.Comm,
		TargetExe:     e.Target.Exe,
		Aux:           e.Aux,
	})
}
