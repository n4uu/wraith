package event

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestMessageFilelessExecViaMemfd(t *testing.T) {
	rule, ok := Lookup(SignalFilelessExec)
	if !ok {
		t.Fatal("fileless_exec rule missing from catalog")
	}

	ev := Event{
		Rule:   rule,
		PID:    4242,
		Comm:   "worker",
		Detail: "payload",
		Aux:    atEmptyPath,
	}

	msg := ev.Message()
	for _, want := range []string{"worker[4242]", "in-memory image", `memfd "payload"`, "AT_EMPTY_PATH"} {
		if !strings.Contains(msg, want) {
			t.Errorf("Message() = %q, want it to contain %q", msg, want)
		}
	}
}

func TestMessagePtraceInject(t *testing.T) {
	rule, _ := Lookup(SignalPtraceInject)
	ev := Event{
		Rule:      rule,
		PID:       10,
		Comm:      "attacker",
		TargetPID: 20,
		Aux:       16, // PTRACE_ATTACH
	}

	msg := ev.Message()
	if !strings.Contains(msg, "PTRACE_ATTACH") {
		t.Errorf("Message() = %q, want the ptrace request name", msg)
	}
	if !strings.Contains(msg, "pid 20") {
		t.Errorf("Message() = %q, want a fallback target label when Target is unset", msg)
	}
}

func TestMessageUsesEnrichedTargetLabel(t *testing.T) {
	rule, _ := Lookup(SignalProcMemWrite)
	ev := Event{
		Rule:      rule,
		PID:       10,
		Comm:      "attacker",
		TargetPID: 20,
		Target:    Process{PID: 20, Comm: "sshd"},
	}

	if msg := ev.Message(); !strings.Contains(msg, "sshd[20]") {
		t.Errorf("Message() = %q, want the enriched target comm to be used", msg)
	}
}

func TestEventJSONRoundTrip(t *testing.T) {
	rule, _ := Lookup(SignalPreloadHijack)
	ev := Event{
		Rule:   rule,
		PID:    99,
		Comm:   "curl",
		Detail: "LD_PRELOAD=/tmp/evil.so",
		Proc:   Process{Exe: "/usr/bin/curl"},
	}

	raw, err := json.Marshal(ev)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}

	var decoded map[string]any
	if err := json.Unmarshal(raw, &decoded); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}

	if decoded["rule"] != "preload_hijack" {
		t.Errorf("rule = %v, want preload_hijack", decoded["rule"])
	}
	if decoded["technique"] != "T1574.006" {
		t.Errorf("technique = %v, want T1574.006", decoded["technique"])
	}
	if decoded["severity"] != "high" {
		t.Errorf("severity = %v, want high", decoded["severity"])
	}
}

func TestParseSeverityRoundTrip(t *testing.T) {
	for sev := SevInfo; sev <= SevCritical; sev++ {
		parsed, err := ParseSeverity(sev.String())
		if err != nil {
			t.Fatalf("ParseSeverity(%q): %v", sev.String(), err)
		}
		if parsed != sev {
			t.Errorf("ParseSeverity(%q) = %v, want %v", sev.String(), parsed, sev)
		}
	}

	if _, err := ParseSeverity("nonsense"); err == nil {
		t.Error("ParseSeverity(\"nonsense\") should error")
	}
}

func TestRuleCatalogIsConsistent(t *testing.T) {
	seen := make(map[string]bool)
	for _, r := range Rules() {
		if r.ID == "" || r.Technique == "" || r.Title == "" {
			t.Errorf("rule %+v has an empty required field", r)
		}
		if seen[r.ID] {
			t.Errorf("duplicate rule id %q", r.ID)
		}
		seen[r.ID] = true

		if _, ok := Lookup(r.Signal); !ok {
			t.Errorf("Lookup cannot find rule for its own signal %d (id %q)", r.Signal, r.ID)
		}
	}
}
