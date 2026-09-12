// SPDX-License-Identifier: GPL-2.0
/*
 * wraith: kernel-side sensor.
 *
 * Every detection rule is its own SEC() program: rules stay independently
 * attachable, independently loadable, and a verifier rejection in one never
 * takes the rest of the sensor down. Programs share nothing but the ring
 * buffer and two small maps.
 */
#include "vmlinux.h"

#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#include "wraith.h"

/*
 * bpf_probe_read_user*() is a GPL-only helper, so the kernel object must
 * declare GPL. The userspace half of this project is MIT; see README.
 */
char LICENSE[] SEC("license") = "GPL";

#define AT_EMPTY_PATH 0x1000

#define PTRACE_POKETEXT 4
#define PTRACE_POKEDATA 5
#define PTRACE_POKEUSR 6
#define PTRACE_SETREGS 13
#define PTRACE_SETFPREGS 15
#define PTRACE_ATTACH 16
#define PTRACE_SETREGSET 0x4205
#define PTRACE_SEIZE 0x4206

#define ENV_SCAN_MAX 20
#define ENV_BUF_LEN 192
#define MEMFD_NAME_LEN 48

/* A memfd is only treated as the source of a later exec inside this window. */
#define MEMFD_CORRELATION_NS (60ULL * 1000000000ULL)

struct memfd_info {
	__u64 ts_ns;
	char name[MEMFD_NAME_LEN];
};

/*
 * struct event only ever appears behind a void* from bpf_ringbuf_reserve(), so
 * nothing would pull it into BTF. This declaration makes the layout visible to
 * bpf2go, which generates the matching Go struct from it.
 */
struct event *unused_event __attribute__((unused));

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 24); /* 16 MiB */
} events SEC(".maps");

/* pid -> most recent memfd_create(), consumed by the exec probes. */
struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 4096);
	__type(key, __u32);
	__type(value, struct memfd_info);
} memfd_pids SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct wraith_cfg);
} config SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, STAT_MAX);
	__type(key, __u32);
	__type(value, __u64);
} stats SEC(".maps");

static __always_inline void stat_bump(__u32 slot)
{
	__u64 *c = bpf_map_lookup_elem(&stats, &slot);
	if (c)
		__sync_fetch_and_add(c, 1);
}

static __always_inline struct wraith_cfg *get_cfg(void)
{
	__u32 key = 0;
	return bpf_map_lookup_elem(&config, &key);
}

/* The sensor must never alert on itself: it would loop through its own probes. */
static __always_inline int is_self(__u32 pid)
{
	struct wraith_cfg *cfg = get_cfg();
	return cfg && cfg->self_pid == pid;
}

static __always_inline __u32 get_ppid(void)
{
	struct task_struct *task = (struct task_struct *)bpf_get_current_task();
	return BPF_CORE_READ(task, real_parent, tgid);
}

static __always_inline struct event *evt_new(__u32 signal)
{
	struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
	if (!e) {
		stat_bump(STAT_DROPPED);
		return NULL;
	}

	__u64 id = bpf_get_current_pid_tgid();

	e->ts_ns = bpf_ktime_get_ns();
	e->aux = 0;
	e->signal = signal;
	e->pid = id >> 32;
	e->tid = (__u32)id;
	e->ppid = get_ppid();
	e->uid = (__u32)bpf_get_current_uid_gid();
	e->target_pid = 0;
	e->path[0] = '\0';
	e->detail[0] = '\0';
	bpf_get_current_comm(&e->comm, sizeof(e->comm));

	return e;
}

static __always_inline void evt_submit(struct event *e)
{
	stat_bump(STAT_EMITTED);
	bpf_ringbuf_submit(e, 0);
}

/*
 * Prefix matching is spelled out byte by byte on purpose: comparing against a
 * .rodata string pointer inside a loop makes the verifier reason about an
 * unbounded map read, while these constant comparisons on a fixed-size stack
 * buffer are trivially safe.
 */
static __always_inline int is_tmpfs_path(const char *p)
{
	if (p[0] == '/' && p[1] == 't' && p[2] == 'm' && p[3] == 'p' && p[4] == '/')
		return 1;
	if (p[0] == '/' && p[1] == 'd' && p[2] == 'e' && p[3] == 'v' && p[4] == '/' &&
	    p[5] == 's' && p[6] == 'h' && p[7] == 'm' && p[8] == '/')
		return 1;
	if (p[0] == '/' && p[1] == 'r' && p[2] == 'u' && p[3] == 'n' && p[4] == '/' &&
	    p[5] == 's' && p[6] == 'h' && p[7] == 'm' && p[8] == '/')
		return 1;
	if (p[0] == '/' && p[1] == 'v' && p[2] == 'a' && p[3] == 'r' && p[4] == '/' &&
	    p[5] == 't' && p[6] == 'm' && p[7] == 'p' && p[8] == '/')
		return 1;
	return 0;
}

/* /dev/fd/N, /proc/self/fd/N and /proc/<pid>/fd/N: the usual way to exec an fd. */
static __always_inline int is_fd_path(const char *p)
{
	if (p[0] == '/' && p[1] == 'd' && p[2] == 'e' && p[3] == 'v' && p[4] == '/' &&
	    p[5] == 'f' && p[6] == 'd' && p[7] == '/')
		return 1;

	if (!(p[0] == '/' && p[1] == 'p' && p[2] == 'r' && p[3] == 'o' && p[4] == 'c' &&
	      p[5] == '/'))
		return 0;

#pragma unroll
	for (int i = 6; i < 24; i++) {
		if (p[i] == '\0')
			return 0;
		if (p[i] == '/' && p[i + 1] == 'f' && p[i + 2] == 'd' && p[i + 3] == '/')
			return 1;
	}
	return 0;
}

static __always_inline int is_loader_hijack_env(const char *e)
{
	if (!(e[0] == 'L' && e[1] == 'D' && e[2] == '_'))
		return 0;

	/* LD_PRELOAD= */
	if (e[3] == 'P' && e[4] == 'R' && e[5] == 'E' && e[6] == 'L' && e[7] == 'O' &&
	    e[8] == 'A' && e[9] == 'D' && e[10] == '=')
		return e[11] != '\0';

	/* LD_AUDIT= */
	if (e[3] == 'A' && e[4] == 'U' && e[5] == 'D' && e[6] == 'I' && e[7] == 'T' &&
	    e[8] == '=')
		return e[9] != '\0';

	return 0;
}

/*
 * Correlate this exec with a recent memfd_create() by the process or its
 * parent: the classic shape is memfd_create() -> write payload -> fork ->
 * execveat(fd, "", AT_EMPTY_PATH), so the exec'ing pid is often the child.
 */
static __always_inline struct memfd_info *recent_memfd(__u32 pid, __u32 ppid, __u64 now)
{
	struct memfd_info *info = bpf_map_lookup_elem(&memfd_pids, &pid);
	if (!info)
		info = bpf_map_lookup_elem(&memfd_pids, &ppid);
	if (!info)
		return NULL;
	if (now - info->ts_ns > MEMFD_CORRELATION_NS)
		return NULL;
	return info;
}

static __always_inline int handle_exec_path(const char *filename, int flags)
{
	__u64 id = bpf_get_current_pid_tgid();
	__u32 pid = id >> 32;

	if (is_self(pid))
		return 0;

	char path[PATH_LEN];
	long n = bpf_probe_read_user_str(path, sizeof(path), filename);
	if (n < 0) {
		path[0] = '\0';
		n = 0;
	}

	__u32 ppid = get_ppid();
	__u64 now = bpf_ktime_get_ns();
	struct memfd_info *memfd = recent_memfd(pid, ppid, now);

	/* execveat(fd, "", AT_EMPTY_PATH) never touches a filesystem path. */
	int empty_path = (flags & AT_EMPTY_PATH) && n <= 1;
	int fileless = empty_path || is_fd_path(path) || memfd != NULL;

	if (fileless) {
		struct event *e = evt_new(SIG_FILELESS_EXEC);
		if (!e)
			return 0;
		e->aux = (__u64)flags;
		bpf_probe_read_kernel_str(e->path, sizeof(e->path), path);
		if (memfd)
			bpf_probe_read_kernel_str(e->detail, sizeof(e->detail), memfd->name);
		evt_submit(e);
		return 0;
	}

	if (is_tmpfs_path(path)) {
		struct event *e = evt_new(SIG_TMPFS_EXEC);
		if (!e)
			return 0;
		e->aux = (__u64)flags;
		bpf_probe_read_kernel_str(e->path, sizeof(e->path), path);
		evt_submit(e);
	}

	return 0;
}

static __always_inline int handle_exec_env(__u64 envp_addr, const char *filename)
{
	__u32 pid = bpf_get_current_pid_tgid() >> 32;

	if (is_self(pid) || !envp_addr)
		return 0;

	const char *const *envp = (const char *const *)envp_addr;
	char buf[ENV_BUF_LEN];

#pragma unroll
	for (int i = 0; i < ENV_SCAN_MAX; i++) {
		const char *entry = NULL;

		if (bpf_probe_read_user(&entry, sizeof(entry), &envp[i]) < 0)
			break;
		if (!entry)
			break;
		if (bpf_probe_read_user_str(buf, sizeof(buf), entry) < 0)
			break;
		if (!is_loader_hijack_env(buf))
			continue;

		struct event *e = evt_new(SIG_PRELOAD_HIJACK);
		if (!e)
			break;
		e->aux = (__u64)i;
		bpf_probe_read_kernel_str(e->detail, sizeof(e->detail), buf);
		/* Read straight into the ring buffer record: the stack budget is
		 * already spent on the env buffer. */
		bpf_probe_read_user_str(e->path, sizeof(e->path), filename);
		evt_submit(e);
		break;
	}

	return 0;
}

SEC("tracepoint/syscalls/sys_enter_execve")
int wraith_execve_path(struct trace_event_raw_sys_enter *ctx)
{
	return handle_exec_path((const char *)ctx->args[0], 0);
}

SEC("tracepoint/syscalls/sys_enter_execve")
int wraith_execve_env(struct trace_event_raw_sys_enter *ctx)
{
	return handle_exec_env((__u64)ctx->args[2], (const char *)ctx->args[0]);
}

SEC("tracepoint/syscalls/sys_enter_execveat")
int wraith_execveat_path(struct trace_event_raw_sys_enter *ctx)
{
	return handle_exec_path((const char *)ctx->args[1], (int)ctx->args[4]);
}

SEC("tracepoint/syscalls/sys_enter_execveat")
int wraith_execveat_env(struct trace_event_raw_sys_enter *ctx)
{
	return handle_exec_env((__u64)ctx->args[3], (const char *)ctx->args[1]);
}

SEC("tracepoint/syscalls/sys_enter_memfd_create")
int wraith_memfd_create(struct trace_event_raw_sys_enter *ctx)
{
	__u32 pid = bpf_get_current_pid_tgid() >> 32;

	if (is_self(pid))
		return 0;

	struct memfd_info info = {};
	info.ts_ns = bpf_ktime_get_ns();
	bpf_probe_read_user_str(info.name, sizeof(info.name), (const char *)ctx->args[0]);
	bpf_map_update_elem(&memfd_pids, &pid, &info, BPF_ANY);

	struct wraith_cfg *cfg = get_cfg();
	if (!cfg || !cfg->emit_info)
		return 0;

	struct event *e = evt_new(SIG_MEMFD_CREATE);
	if (!e)
		return 0;
	e->aux = (__u64)ctx->args[1]; /* flags */
	bpf_probe_read_kernel_str(e->detail, sizeof(e->detail), info.name);
	evt_submit(e);

	return 0;
}

SEC("tracepoint/sched/sched_process_exit")
int wraith_process_exit(void *ctx)
{
	__u32 pid = bpf_get_current_pid_tgid() >> 32;

	/* Keeps pid reuse from resurrecting a stale memfd correlation. */
	bpf_map_delete_elem(&memfd_pids, &pid);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_process_vm_writev")
int wraith_process_vm_writev(struct trace_event_raw_sys_enter *ctx)
{
	__u32 pid = bpf_get_current_pid_tgid() >> 32;
	__u32 target = (__u32)ctx->args[0];

	if (is_self(pid) || target == pid || target == 0)
		return 0;

	struct event *e = evt_new(SIG_PROC_MEM_WRITE);
	if (!e)
		return 0;
	e->target_pid = target;
	e->aux = (__u64)ctx->args[4]; /* riovcnt */
	evt_submit(e);

	return 0;
}

SEC("tracepoint/syscalls/sys_enter_ptrace")
int wraith_ptrace(struct trace_event_raw_sys_enter *ctx)
{
	__u32 pid = bpf_get_current_pid_tgid() >> 32;
	__u64 request = (__u64)ctx->args[0];
	__u32 target = (__u32)ctx->args[1];

	if (is_self(pid) || target == pid || target == 0)
		return 0;

	switch (request) {
	case PTRACE_POKETEXT:
	case PTRACE_POKEDATA:
	case PTRACE_POKEUSR:
	case PTRACE_SETREGS:
	case PTRACE_SETFPREGS:
	case PTRACE_ATTACH:
	case PTRACE_SETREGSET:
	case PTRACE_SEIZE:
		break;
	default:
		return 0;
	}

	struct event *e = evt_new(SIG_PTRACE_INJECT);
	if (!e)
		return 0;
	e->target_pid = target;
	e->aux = request;
	evt_submit(e);

	return 0;
}
