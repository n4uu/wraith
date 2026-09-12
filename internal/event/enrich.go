package event

import (
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	deletedSuffix  = " (deleted)"
	maxCmdlineLen  = 240
	enricherMaxLen = 4096
)

// containerIDPattern matches the 64-hex id embedded in docker, containerd,
// CRI-O and podman cgroup paths.
var containerIDPattern = regexp.MustCompile(`[0-9a-f]{64}`)

type cacheEntry struct {
	proc Process
	at   time.Time
}

// Enricher resolves pids to process context through procfs.
//
// Results are cached briefly: an exec storm would otherwise turn every alert
// into a handful of synchronous procfs reads.
type Enricher struct {
	root string
	ttl  time.Duration
	now  func() time.Time

	mu    sync.Mutex
	cache map[uint32]cacheEntry
}

// NewEnricher reads through root, normally "/proc".
func NewEnricher(root string) *Enricher {
	if root == "" {
		root = "/proc"
	}
	return &Enricher{
		root:  root,
		ttl:   2 * time.Second,
		now:   time.Now,
		cache: make(map[uint32]cacheEntry),
	}
}

// Enrich fills in the process context for an event in place.
func (e *Enricher) Enrich(ev *Event) {
	ev.Proc = e.Process(ev.PID)
	if ev.Proc.Comm == "" {
		ev.Proc.Comm = ev.Comm
	}
	if ev.PPID != 0 {
		ev.Parent = e.Process(ev.PPID)
	}
	if ev.TargetPID != 0 {
		ev.Target = e.Process(ev.TargetPID)
	}
}

// Process returns what procfs still knows about pid. Short-lived processes are
// routinely gone by the time an alert is handled, so missing fields are normal
// and never an error.
func (e *Enricher) Process(pid uint32) Process {
	if pid == 0 {
		return Process{}
	}

	now := e.now()
	e.mu.Lock()
	if entry, ok := e.cache[pid]; ok && now.Sub(entry.at) < e.ttl {
		e.mu.Unlock()
		return entry.proc
	}
	e.mu.Unlock()

	proc := e.read(pid)

	e.mu.Lock()
	if len(e.cache) >= enricherMaxLen {
		e.cache = make(map[uint32]cacheEntry)
	}
	e.cache[pid] = cacheEntry{proc: proc, at: now}
	e.mu.Unlock()

	return proc
}

func (e *Enricher) read(pid uint32) Process {
	dir := filepath.Join(e.root, strconv.FormatUint(uint64(pid), 10))
	proc := Process{PID: pid}

	if exe, err := os.Readlink(filepath.Join(dir, "exe")); err == nil {
		proc.Deleted = strings.HasSuffix(exe, deletedSuffix)
		proc.Exe = strings.TrimSuffix(exe, deletedSuffix)
	}
	if comm, err := os.ReadFile(filepath.Join(dir, "comm")); err == nil {
		proc.Comm = strings.TrimSpace(string(comm))
	}
	if raw, err := os.ReadFile(filepath.Join(dir, "cmdline")); err == nil {
		proc.Cmdline = formatCmdline(raw)
	}
	if cgroup, err := os.ReadFile(filepath.Join(dir, "cgroup")); err == nil {
		proc.Container = containerID(string(cgroup))
	}

	return proc
}

func formatCmdline(raw []byte) string {
	args := strings.FieldsFunc(string(raw), func(r rune) bool { return r == 0 })
	line := strings.Join(args, " ")
	if len(line) > maxCmdlineLen {
		line = line[:maxCmdlineLen] + "…"
	}
	return line
}

// containerID extracts the short container id from a cgroup file, if the
// process belongs to one.
func containerID(cgroup string) string {
	match := containerIDPattern.FindString(cgroup)
	if match == "" {
		return ""
	}
	return match[:12]
}
