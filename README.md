# wraith

[![ci](https://github.com/n4uu/wraith/actions/workflows/ci.yml/badge.svg)](https://github.com/n4uu/wraith/actions/workflows/ci.yml)
[![Go Reference](https://pkg.go.dev/badge/github.com/n4uu/wraith.svg)](https://pkg.go.dev/github.com/n4uu/wraith)
[![Go Report Card](https://goreportcard.com/badge/github.com/n4uu/wraith)](https://goreportcard.com/report/github.com/n4uu/wraith)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

**An eBPF sensor for the userland primitives behind fileless execution and
process injection on Linux.**

wraith watches six syscalls at the tracepoint level (`execve`, `execveat`,
`memfd_create`, `process_vm_writev`, `ptrace`, and process exit for
bookkeeping) and flags the specific argument patterns that separate normal
process lifecycle from a payload that never touched disk, a loader hijacked
via `LD_PRELOAD`, or one process reaching into another's memory. No agent-side
heuristics on file hashes, no cloud lookup: every rule is a fact about a
single syscall's arguments, decided in-kernel before the event is even copied
to userspace.

Captured verbatim from `scripts/simulate` running against a live `sudo wraith`
on a stock Kali kernel. Every line below is a real detection, not a mockup:

```
$ sudo wraith
wraith dev: watching for in-memory execution and process injection (min severity: low)
press ctrl-c to stop

19:41:14.315 CRITICAL fileless_exec   T1620      fileless_exec[126213] executed an in-memory image (memfd "wraith-demo") via execveat(AT_EMPTY_PATH)
    └─ uid=1000  exe=/home/n4uu/wraith/scripts/simulate/fileless_exec  parent=bash[126169]  cmdline=./scripts/simulate/fileless_exec
19:41:14.320 HIGH     ptrace_inject   T1055.008  proc_injection[126214] issued PTRACE_ATTACH against proc_injection[126215]
    └─ uid=1000  exe=/home/n4uu/wraith/scripts/simulate/proc_injection  parent=bash[126169]  target_exe=/home/n4uu/wraith/scripts/simulate/proc_injection  cmdline=./scripts/simulate/proc_injection
19:41:14.320 CRITICAL proc_mem_write  T1055.009  proc_injection[126214] wrote into proc_injection[126215] via process_vm_writev (1 remote iovec(s))
    └─ uid=1000  exe=/home/n4uu/wraith/scripts/simulate/proc_injection  parent=bash[126169]  target_exe=/home/n4uu/wraith/scripts/simulate/proc_injection  cmdline=./scripts/simulate/proc_injection
19:41:14.331 MEDIUM   tmpfs_exec      T1036      bash[126220] executed /tmp/wraith-demo.5Hx4Na from a world-writable path
    └─ uid=1000  exe=/tmp/wraith-demo.5Hx4Na  parent=bash[126216]  cmdline=/tmp/wraith-demo.5Hx4Na
19:41:14.345 HIGH     preload_hijack  T1574.006  bash[126227] launched /bin/true with LD_PRELOAD=/home/n4uu/wraith/scripts/simulate/preload_lib.so
    └─ uid=1000  exe=/usr/bin/true  parent=bash[126222]

5 signal(s) raised by the kernel, 0 deduplicated
```

Note `preload_hijack`'s `exe=/usr/bin/true`: the probe fires at `sys_enter`,
before the syscall runs, but enrichment happens a moment later when the
event is dequeued in userspace. By then `/proc/<pid>/exe` usually already
points at the image the exec just switched to, so alerts show what actually
ended up running, not just what was requested.

## What it catches

| Rule | Severity | ATT&CK | What fires it |
| --- | --- | --- | --- |
| `fileless_exec` | Critical | [T1620](https://attack.mitre.org/techniques/T1620/) Reflective Code Loading | `execveat(fd, "", AT_EMPTY_PATH)`, a path under `/proc/*/fd/` or `/dev/fd/`, or an exec correlated with a recent `memfd_create` in the same process tree. |
| `proc_mem_write` | Critical | [T1055.009](https://attack.mitre.org/techniques/T1055/009/) Process Injection: Proc Memory | `process_vm_writev` targeting a *different* pid. |
| `preload_hijack` | High | [T1574.006](https://attack.mitre.org/techniques/T1574/006/) Dynamic Linker Hijacking | `LD_PRELOAD=` or `LD_AUDIT=` present in the environment of a new `execve`/`execveat`. |
| `ptrace_inject` | High | [T1055.008](https://attack.mitre.org/techniques/T1055/008/) Process Injection: Ptrace | `ptrace()` against another pid with a request that attaches to it or mutates its registers/memory (`PTRACE_ATTACH`, `PTRACE_SEIZE`, `PTRACE_SETREGS`, `PTRACE_POKE*`, …). |
| `tmpfs_exec` | Medium | [T1036](https://attack.mitre.org/techniques/T1036/) Masquerading | Exec from `/tmp`, `/var/tmp`, `/dev/shm` or `/run/shm`. |
| `memfd_create` | Info | T1620 (context) | Every `memfd_create` call, correlated by the rule above. Off by default (`-info` to enable), since legitimate runtimes (Chromium, systemd, Firefox) use it too. |

Every alert is enriched from `/proc` before it reaches a sink: the actor's
`exe` (and whether that file has since been deleted or was never linked, the
signature of an unpacked-and-removed dropper), its `cmdline`, its container
id if it's running in one, and the same for the parent and, for the
injection rules, the target process.

## Why tracepoints, not LSM hooks or a userland hash-check

The six syscalls above are the *only* legal ways to do these things on Linux.
There is no other path to running code from an fd-backed image or writing
into a foreign address space. A rule reasoning directly about syscall
arguments, in-kernel, catches every caller of that syscall by construction,
with none of the TOCTOU gap a userland process-list scanner has, and none of
the LSM hook availability requirements a security-module-based tool would
carry. The trade-off is scope: wraith is a small, auditable set of six rules
around fileless execution and injection, not a general-purpose EDR. See
[Limitations](#limitations) for what it deliberately does not attempt.

## Architecture

```
                     kernel space                     │  userspace
                                                        │
 sys_enter_execve ────┐                                │
 sys_enter_execveat ──┼──▶ wraith_*_path/env  ─┐        │
 sys_enter_memfd_create ─▶ wraith_memfd_create ├─▶ ring buffer ─▶ decode ─▶ /proc enrich ─▶ filter ─▶ sinks
 sys_enter_process_vm_writev ▶ wraith_proc_vm_writev │        │                                   (console/JSONL/webhook)
 sys_enter_ptrace ────────▶ wraith_ptrace       │        │
 sched_process_exit ──────▶ wraith_process_exit ┘  LRU map: pid → recent memfd
                                                (feeds the fileless_exec correlation)
```

Each rule is its own `SEC()` program attached independently, so a tracepoint
missing on an older kernel costs that one rule (reported as a warning at
startup), not the whole sensor. All eight programs share only two small maps:
an LRU hash correlating `memfd_create` with the exec that follows it, and a
one-entry config map (the sensor's own pid, so it never alerts on itself, and
whether info-level signals are on).

Kernel side (`bpf/wraith.bpf.c`) is C compiled with clang to BPF bytecode and
verified by the kernel at load time. See [How each rule is
implemented](#how-each-rule-is-implemented) for the reasoning behind each
one. Userspace (`internal/`) is Go, using
[cilium/ebpf](https://github.com/cilium/ebpf) for loading/attachment,
nothing else for the core path.

## Requirements

- Linux 5.8+ (ring buffer maps) with `CONFIG_DEBUG_INFO_BTF=y`. Check with
  `ls /sys/kernel/btf/vmlinux`.
- `CAP_BPF` + `CAP_PERFMON`, or root. Nothing is written or modified outside
  the sensor's own maps: every capability is used for observation only.
- No runtime dependency on clang/LLVM or kernel headers. The compiled BPF
  object is committed and embedded into the binary via `go:embed`.

## Build & run

Prebuilt binaries for Linux (amd64 and arm64) are on the
[releases page](https://github.com/n4uu/wraith/releases/latest). They're built
by GitHub Actions from the tagged commit, never on a workstation, and every
archive carries a signed build provenance attestation:

```sh
gh attestation verify wraith_*_linux_amd64.tar.gz -R n4uu/wraith
```

To build from source instead:

```sh
git clone https://github.com/n4uu/wraith
cd wraith
make build
sudo ./bin/wraith
```

```sh
sudo ./bin/wraith -json                                   # JSON Lines to stdout
sudo ./bin/wraith -webhook https://hooks.slack.com/...     # also push to Slack/Discord/any HTTP receiver
sudo ./bin/wraith -min-severity high                       # only high and critical
sudo ./bin/wraith -exclude-comm containerd,dockerd         # quiet known-noisy comms
sudo ./bin/wraith -list-rules                              # print the detection catalog and exit
```

## See it fire, without a real sample

Every detection has a benign, self-contained reproduction under
[`scripts/simulate`](scripts/simulate): a couple of small C programs and
shell scripts that trigger each rule using nothing but `/bin/true`, a no-op
shared object, and a string written into a scratch buffer. Run `sudo
./bin/wraith` in one terminal and drive the scripts from
[`scripts/simulate/README.md`](scripts/simulate/README.md) from another to
watch every rule fire end to end.

## How each rule is implemented

**`fileless_exec`**: `execveat(fd, "", AT_EMPTY_PATH)` is the direct
form (empty path, flag set) and is checked first. The indirect form,
`execve("/proc/self/fd/N", …)`, is checked byte by byte against `/proc/*/fd/`
and `/dev/fd/` prefixes rather than with a loop over a `.rodata` string,
because the BPF verifier can reason about a fixed sequence of constant
comparisons on a stack buffer far more easily than about a bounded loop over
memory it can't prove the length of. The `memfd_create` correlation catches
the remaining case, `fork()` after `memfd_create()`, then an ordinary
`execve` of an unrelated-looking path in the child, by keying an LRU map on
pid and checking it (and the parent's entry) from the exec probes, inside a
60-second window.

**`preload_hijack`**: reading `envp` from userspace requires walking an
array of pointers with `bpf_probe_read_user`, capped at a fixed 20-entry
unrolled loop (the verifier requires a statically boundable trip count); each
entry is read into a stack buffer and compared against `LD_PRELOAD=` /
`LD_AUDIT=` prefixes the same way exec paths are: byte comparisons, not a
string routine.

**`proc_mem_write` / `ptrace_inject`**: both are a single argument check
(target pid != caller pid for `process_vm_writev`; target pid != caller and
request is memory/register-mutating or attach-class for `ptrace`) against
the tracepoint's own argument array. No state, no correlation. These two
syscalls have no legitimate reason to target a different pid outside a
debugger, and debugging your own tooling is expected to be somewhat noisy
under wraith by design (see [Limitations](#limitations)).

**`tmpfs_exec`**: the executed path checked against `/tmp/`, `/var/tmp/`,
`/dev/shm/` and `/run/shm/` prefixes.

## Limitations

This is a research/detection-engineering project, not a production EDR, and
it has real, specific blind spots:

- **A root-level adversary can unload it.** Anything running as root can
  unload any eBPF program, wraith included. It observes; it does not
  self-protect, lock its own maps against a privileged detacher, or attempt
  to survive one.
- **It cannot see below the syscall boundary.** A kernel module, a
  `bpf()`-based rootkit hooking the same tracepoints, or direct hardware
  access are all out of scope. wraith's entire visibility is the six
  syscalls it hooks.
- **Every rule is a heuristic on a legitimate primitive**, not a proof of
  malice. Debuggers (`gdb`, `strace -p`), CRIU-style checkpoint/restore
  tools, and some sandboxes/anti-cheat software use `ptrace` and
  `process_vm_writev` against other processes routinely, and `LD_PRELOAD`
  has entirely legitimate uses (`libeatmydata`, ASan, jemalloc). Expect to
  tune `-exclude-comm` and `-min-severity` for your environment; none of
  these rules are a verdict on their own.
- **No network or file-write visibility.** wraith answers "did something
  just execute in-memory or reach into another process," not "is this host
  compromised." Pair it with your existing file-integrity and network
  monitoring; it isn't a replacement for either.
- **PID reuse inside the correlation window.** The `memfd_create` → exec
  correlation is keyed on pid with a 60-second TTL; a pid recycled by the
  kernel inside that window before the LRU entry ages out could in theory
  inherit a stale correlation. Given typical exec latency this is a
  theoretical gap, not one that's been observed in testing.

## Development

```sh
make test              # go test ./...
make vet               # go vet ./...
make generate           # regenerate the BPF Go bindings after editing bpf/wraith.bpf.c (needs clang)
make simulate           # build the demo binaries under scripts/simulate
```

## License

The Go userspace code (`cmd/`, `internal/`) is MIT, see [LICENSE](LICENSE).
The kernel-side program (`bpf/wraith.bpf.c`) is licensed GPL-2.0, which the
kernel requires for the GPL-only helpers it calls (`bpf_probe_read_user*`).
This is the same split used by most eBPF tooling with a permissively
licensed userspace half.
