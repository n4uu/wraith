package output

import (
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"github.com/n4uu/wraith/internal/event"
)

const dedupMaxEntries = 8192

// Filter decides which events reach the sinks.
type Filter struct {
	minSeverity  event.Severity
	excludeComms map[string]struct{}
	dedupWindow  time.Duration

	mu   sync.Mutex
	seen map[string]time.Time
	now  func() time.Time

	suppressed atomic.Uint64
}

// NewFilter builds a filter. A zero dedupWindow disables deduplication.
func NewFilter(minSeverity event.Severity, excludeComms []string, dedupWindow time.Duration) *Filter {
	excluded := make(map[string]struct{}, len(excludeComms))
	for _, comm := range excludeComms {
		if comm != "" {
			excluded[comm] = struct{}{}
		}
	}
	return &Filter{
		minSeverity:  minSeverity,
		excludeComms: excluded,
		dedupWindow:  dedupWindow,
		seen:         make(map[string]time.Time),
		now:          time.Now,
	}
}

// Allow reports whether the event should be emitted.
func (f *Filter) Allow(ev event.Event) bool {
	if ev.Rule.Severity < f.minSeverity {
		return false
	}
	if _, excluded := f.excludeComms[ev.Comm]; excluded {
		return false
	}
	if f.dedupWindow <= 0 {
		return true
	}
	return f.firstInWindow(ev)
}

// firstInWindow collapses repeats of the same alert: a process that execs in a
// loop should produce one line, not a thousand.
func (f *Filter) firstInWindow(ev event.Event) bool {
	key := fmt.Sprintf("%s|%d|%d|%s|%s", ev.Rule.ID, ev.PID, ev.TargetPID, ev.Path, ev.Detail)
	now := f.now()

	f.mu.Lock()
	defer f.mu.Unlock()

	if last, ok := f.seen[key]; ok && now.Sub(last) < f.dedupWindow {
		f.suppressed.Add(1)
		return false
	}

	if len(f.seen) >= dedupMaxEntries {
		for k, ts := range f.seen {
			if now.Sub(ts) >= f.dedupWindow {
				delete(f.seen, k)
			}
		}
	}

	f.seen[key] = now
	return true
}

// Suppressed counts events dropped by deduplication.
func (f *Filter) Suppressed() uint64 { return f.suppressed.Load() }
