package output

import (
	"testing"
	"time"

	"github.com/n4uu/wraith/internal/event"
)

func mustRule(t *testing.T, sig event.Signal) event.Rule {
	t.Helper()
	r, ok := event.Lookup(sig)
	if !ok {
		t.Fatalf("no rule registered for signal %d", sig)
	}
	return r
}

func TestFilterMinSeverity(t *testing.T) {
	f := NewFilter(event.SevHigh, nil, 0)

	medium := event.Event{Rule: mustRule(t, event.SignalTmpfsExec)} // medium
	if f.Allow(medium) {
		t.Error("medium-severity event should be blocked when min severity is high")
	}

	critical := event.Event{Rule: mustRule(t, event.SignalFilelessExec)} // critical
	if !f.Allow(critical) {
		t.Error("critical-severity event should pass when min severity is high")
	}
}

func TestFilterExcludeComm(t *testing.T) {
	f := NewFilter(event.SevInfo, []string{"systemd", "containerd"}, 0)

	blocked := event.Event{Rule: mustRule(t, event.SignalFilelessExec), Comm: "systemd"}
	if f.Allow(blocked) {
		t.Error("event from an excluded comm should be blocked")
	}

	allowed := event.Event{Rule: mustRule(t, event.SignalFilelessExec), Comm: "bash"}
	if !f.Allow(allowed) {
		t.Error("event from a non-excluded comm should pass")
	}
}

func TestFilterDedup(t *testing.T) {
	now := time.Unix(0, 0)
	f := NewFilter(event.SevInfo, nil, 5*time.Second)
	f.now = func() time.Time { return now }

	ev := event.Event{Rule: mustRule(t, event.SignalFilelessExec), PID: 1234, Path: "/dev/fd/3"}

	if !f.Allow(ev) {
		t.Fatal("first occurrence must always be allowed")
	}
	if f.Allow(ev) {
		t.Fatal("repeat within the dedup window must be suppressed")
	}
	if got := f.Suppressed(); got != 1 {
		t.Fatalf("Suppressed() = %d, want 1", got)
	}

	now = now.Add(6 * time.Second)
	if !f.Allow(ev) {
		t.Fatal("repeat after the dedup window must be allowed again")
	}
}

func TestFilterDedupDistinguishesKeys(t *testing.T) {
	f := NewFilter(event.SevInfo, nil, 5*time.Second)

	a := event.Event{Rule: mustRule(t, event.SignalFilelessExec), PID: 1, Path: "/dev/fd/3"}
	b := event.Event{Rule: mustRule(t, event.SignalFilelessExec), PID: 2, Path: "/dev/fd/4"}

	if !f.Allow(a) || !f.Allow(b) {
		t.Fatal("distinct pid/path combinations must not collide in the dedup key")
	}
}

func TestFilterDedupDisabled(t *testing.T) {
	f := NewFilter(event.SevInfo, nil, 0)
	ev := event.Event{Rule: mustRule(t, event.SignalFilelessExec), PID: 1234}

	for i := 0; i < 3; i++ {
		if !f.Allow(ev) {
			t.Fatalf("iteration %d: dedup window of 0 must disable deduplication", i)
		}
	}
}
