package event

import (
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"
)

// fakeProc builds a minimal /proc/<pid>/{exe,comm,cmdline,cgroup} tree so the
// enricher can be tested without touching the real procfs.
func fakeProc(t *testing.T, root string, pid uint32, exe, comm, cgroup string, cmdline []string) {
	t.Helper()

	dir := filepath.Join(root, strconv.FormatUint(uint64(pid), 10))
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}

	if exe != "" {
		target := filepath.Join(root, "target-"+strconv.FormatUint(uint64(pid), 10))
		if err := os.WriteFile(target, nil, 0o644); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(target, filepath.Join(dir, "exe")); err != nil {
			t.Fatal(err)
		}
		if exe == "deleted" {
			os.Remove(target)
			os.Remove(filepath.Join(dir, "exe"))
			if err := os.Symlink(target+" (deleted)", filepath.Join(dir, "exe")); err != nil {
				t.Fatal(err)
			}
		}
	}

	if comm != "" {
		if err := os.WriteFile(filepath.Join(dir, "comm"), []byte(comm+"\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	if len(cmdline) > 0 {
		var raw []byte
		for _, arg := range cmdline {
			raw = append(raw, []byte(arg)...)
			raw = append(raw, 0)
		}
		if err := os.WriteFile(filepath.Join(dir, "cmdline"), raw, 0o644); err != nil {
			t.Fatal(err)
		}
	}

	if cgroup != "" {
		if err := os.WriteFile(filepath.Join(dir, "cgroup"), []byte(cgroup), 0o644); err != nil {
			t.Fatal(err)
		}
	}
}

func TestEnricherReadsProcess(t *testing.T) {
	root := t.TempDir()
	fakeProc(t, root, 100, "ok", "curl", "0::/system.slice/docker-"+
		"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.scope\n",
		[]string{"curl", "-s", "https://example.invalid"})

	e := NewEnricher(root)
	proc := e.Process(100)

	if proc.Comm != "curl" {
		t.Errorf("Comm = %q, want curl", proc.Comm)
	}
	if proc.Deleted {
		t.Error("Deleted = true, want false")
	}
	if proc.Cmdline != "curl -s https://example.invalid" {
		t.Errorf("Cmdline = %q", proc.Cmdline)
	}
	if proc.Container != "aaaaaaaaaaaa" {
		t.Errorf("Container = %q, want the first 12 hex chars", proc.Container)
	}
}

func TestEnricherDetectsDeletedExe(t *testing.T) {
	root := t.TempDir()
	fakeProc(t, root, 200, "deleted", "payload", "", nil)

	proc := NewEnricher(root).Process(200)
	if !proc.Deleted {
		t.Error("Deleted = false, want true for an unlinked backing file")
	}
}

func TestEnricherMissingProcessIsNotAnError(t *testing.T) {
	proc := NewEnricher(t.TempDir()).Process(999999)
	if proc.PID != 999999 {
		t.Errorf("PID = %d, want the pid to still be set", proc.PID)
	}
	if proc.Comm != "" || proc.Exe != "" {
		t.Errorf("expected empty fields for a vanished process, got %+v", proc)
	}
}

func TestEnricherCachesWithinTTL(t *testing.T) {
	root := t.TempDir()
	fakeProc(t, root, 300, "", "first", "", nil)

	now := time.Unix(0, 0)
	e := NewEnricher(root)
	e.now = func() time.Time { return now }

	if got := e.Process(300).Comm; got != "first" {
		t.Fatalf("Comm = %q, want first", got)
	}

	fakeProc(t, root, 300, "", "second", "", nil)
	if got := e.Process(300).Comm; got != "first" {
		t.Errorf("Comm = %q, want the cached value to still be served within the TTL", got)
	}

	now = now.Add(3 * time.Second)
	if got := e.Process(300).Comm; got != "second" {
		t.Errorf("Comm = %q, want a refreshed value once the TTL has elapsed", got)
	}
}

func TestEnrichPopulatesEvent(t *testing.T) {
	root := t.TempDir()
	fakeProc(t, root, 10, "", "child", "", nil)
	fakeProc(t, root, 1, "", "parent", "", nil)
	fakeProc(t, root, 20, "", "victim", "", nil)

	e := NewEnricher(root)
	ev := Event{PID: 10, PPID: 1, TargetPID: 20, Comm: "child"}
	e.Enrich(&ev)

	if ev.Proc.Comm != "child" || ev.Parent.Comm != "parent" || ev.Target.Comm != "victim" {
		t.Errorf("Enrich did not populate all three process contexts: %+v", ev)
	}
}
