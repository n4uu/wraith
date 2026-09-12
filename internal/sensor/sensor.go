// Package sensor loads the kernel-side probes and turns ring buffer records
// into enriched events.
package sensor

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
	"golang.org/x/sys/unix"

	"github.com/n4uu/wraith/internal/event"
)

// The compiler and strip binary come from BPF2GO_CC / BPF2GO_STRIP so the
// Makefile can point at a versioned toolchain without editing this directive.
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -type event -target amd64,arm64 -cflags "-O2 -g -Wall -Werror" wraith ../../bpf/wraith.bpf.c -- -I../../bpf/include -I../../bpf

// Config tunes what the kernel side reports.
type Config struct {
	// EmitInfo turns on informational signals (memfd_create on its own).
	EmitInfo bool
	// ProcRoot overrides the procfs mount used for enrichment; tests set it.
	ProcRoot string
}

type bpfConfig struct {
	SelfPID  uint32
	EmitInfo uint32
}

type probe struct {
	group   string
	name    string
	program func(*wraithObjects) *ebpf.Program
}

// probes maps every kernel program to the tracepoint it attaches to.
var probes = []probe{
	{"syscalls", "sys_enter_execve", func(o *wraithObjects) *ebpf.Program { return o.WraithExecvePath }},
	{"syscalls", "sys_enter_execve", func(o *wraithObjects) *ebpf.Program { return o.WraithExecveEnv }},
	{"syscalls", "sys_enter_execveat", func(o *wraithObjects) *ebpf.Program { return o.WraithExecveatPath }},
	{"syscalls", "sys_enter_execveat", func(o *wraithObjects) *ebpf.Program { return o.WraithExecveatEnv }},
	{"syscalls", "sys_enter_memfd_create", func(o *wraithObjects) *ebpf.Program { return o.WraithMemfdCreate }},
	{"syscalls", "sys_enter_process_vm_writev", func(o *wraithObjects) *ebpf.Program { return o.WraithProcessVmWritev }},
	{"syscalls", "sys_enter_ptrace", func(o *wraithObjects) *ebpf.Program { return o.WraithPtrace }},
	{"sched", "sched_process_exit", func(o *wraithObjects) *ebpf.Program { return o.WraithProcessExit }},
}

// Sensor owns the loaded programs, their attachments and the ring buffer.
type Sensor struct {
	objs     wraithObjects
	links    []link.Link
	reader   *ringbuf.Reader
	enricher *event.Enricher
	bootTime time.Time

	// Warnings records probes that could not be attached. A kernel missing a
	// tracepoint costs that one rule, not the whole sensor.
	Warnings []string
}

// Stats reports kernel-side counters.
type Stats struct {
	Emitted uint64
	Dropped uint64
}

// Load verifies and attaches every probe.
func Load(cfg Config) (*Sensor, error) {
	if err := rlimit.RemoveMemlock(); err != nil {
		return nil, fmt.Errorf("raise memlock rlimit: %w", err)
	}

	s := &Sensor{
		enricher: event.NewEnricher(cfg.ProcRoot),
		bootTime: bootTime(),
	}

	if err := loadWraithObjects(&s.objs, nil); err != nil {
		var ve *ebpf.VerifierError
		if errors.As(err, &ve) {
			return nil, fmt.Errorf("verifier rejected a program:\n%+v", ve)
		}
		return nil, fmt.Errorf("load bpf objects: %w", err)
	}

	emitInfo := uint32(0)
	if cfg.EmitInfo {
		emitInfo = 1
	}
	runtimeCfg := bpfConfig{SelfPID: uint32(os.Getpid()), EmitInfo: emitInfo}
	if err := s.objs.Config.Put(uint32(0), runtimeCfg); err != nil {
		s.Close()
		return nil, fmt.Errorf("write sensor config: %w", err)
	}

	for _, p := range probes {
		l, err := link.Tracepoint(p.group, p.name, p.program(&s.objs), nil)
		if err != nil {
			s.Warnings = append(s.Warnings,
				fmt.Sprintf("%s:%s not attached (%v)", p.group, p.name, err))
			continue
		}
		s.links = append(s.links, l)
	}
	if len(s.links) == 0 {
		s.Close()
		return nil, errors.New("no probe could be attached: is this kernel built with tracepoint support?")
	}

	reader, err := ringbuf.NewReader(s.objs.Events)
	if err != nil {
		s.Close()
		return nil, fmt.Errorf("open ring buffer: %w", err)
	}
	s.reader = reader

	return s, nil
}

// Run delivers events to handle until ctx is cancelled.
func (s *Sensor) Run(ctx context.Context, handle func(event.Event)) error {
	go func() {
		<-ctx.Done()
		s.reader.Close()
	}()

	for {
		record, err := s.reader.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) || errors.Is(err, os.ErrClosed) {
				return nil
			}
			return fmt.Errorf("read ring buffer: %w", err)
		}

		ev, ok := s.decode(record.RawSample)
		if !ok {
			continue
		}
		handle(ev)
	}
}

func (s *Sensor) decode(sample []byte) (event.Event, bool) {
	var raw wraithEvent
	if err := binary.Read(bytes.NewReader(sample), binary.NativeEndian, &raw); err != nil {
		return event.Event{}, false
	}

	rule, ok := event.Lookup(event.Signal(raw.Signal))
	if !ok {
		return event.Event{}, false
	}

	ev := event.Event{
		Time:      s.bootTime.Add(time.Duration(raw.TsNs)),
		Rule:      rule,
		PID:       raw.Pid,
		TID:       raw.Tid,
		PPID:      raw.Ppid,
		UID:       raw.Uid,
		Comm:      cstring(raw.Comm[:]),
		Path:      cstring(raw.Path[:]),
		Detail:    cstring(raw.Detail[:]),
		TargetPID: raw.TargetPid,
		Aux:       raw.Aux,
	}
	s.enricher.Enrich(&ev)

	return ev, true
}

// Stats sums the per-CPU kernel counters.
func (s *Sensor) Stats() (Stats, error) {
	var out Stats

	read := func(key uint32) (uint64, error) {
		var perCPU []uint64
		if err := s.objs.Stats.Lookup(key, &perCPU); err != nil {
			return 0, err
		}
		var total uint64
		for _, v := range perCPU {
			total += v
		}
		return total, nil
	}

	emitted, err := read(0)
	if err != nil {
		return out, fmt.Errorf("read emitted counter: %w", err)
	}
	dropped, err := read(1)
	if err != nil {
		return out, fmt.Errorf("read dropped counter: %w", err)
	}

	out.Emitted, out.Dropped = emitted, dropped
	return out, nil
}

// Close detaches every probe and releases the maps.
func (s *Sensor) Close() error {
	if s.reader != nil {
		s.reader.Close()
	}
	for _, l := range s.links {
		l.Close()
	}
	return s.objs.Close()
}

// bootTime anchors the kernel's monotonic timestamps to wall clock time.
func bootTime() time.Time {
	var ts unix.Timespec
	if err := unix.ClockGettime(unix.CLOCK_BOOTTIME, &ts); err != nil {
		return time.Now()
	}
	return time.Now().Add(-time.Duration(ts.Nano()))
}

func cstring(b []byte) string {
	if i := bytes.IndexByte(b, 0); i >= 0 {
		b = b[:i]
	}
	return string(b)
}
