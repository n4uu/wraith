# Simulations

Every program here is a benign reproduction of one detection technique. No
malware, no packed payloads, no real-world targeting. Each one triggers
exactly one or two wraith rules and then exits cleanly (`/bin/true`,
`sleep`, and a few bytes written into a scratch buffer are the extent of the
"payload"). They exist so a reviewer, or you, can watch wraith fire without
needing an actual sample.

Run wraith in one terminal:

```sh
sudo ./wraith
```

Then, in another terminal:

```sh
make -C scripts/simulate all      # builds the two small C helpers
./scripts/simulate/fileless_exec.sh
./scripts/simulate/preload_hijack.sh
./scripts/simulate/tmpfs_exec.sh
./scripts/simulate/proc_injection.sh
```

| Script | Rule(s) triggered | Technique it stands in for |
| --- | --- | --- |
| `fileless_exec.sh` | `fileless_exec` (+ `memfd_create` with `-info`) | Copying `/bin/true` into a `memfd` and `fexecve`-ing it, the same primitive droppers use to run a payload that never touches disk. |
| `preload_hijack.sh` | `preload_hijack` | Forcing a locally-built, no-op shared object into `/bin/true` via `LD_PRELOAD`. |
| `tmpfs_exec.sh` | `tmpfs_exec` | Copying `/bin/true` into `/tmp` and executing it from there. |
| `proc_injection.sh` | `ptrace_inject`, `proc_mem_write` | A parent forks a child, `PTRACE_ATTACH`/`PTRACE_DETACH`es it, then overwrites a buffer in its address space with `process_vm_writev`: the two userland primitives behind Linux process injection, used here to write a harmless string instead of shellcode. |

`proc_injection` only attaches to its own child, so it works even under the
default (`ptrace_scope=1`) Yama restriction. No capabilities beyond what
your shell already has are required for any of these.
