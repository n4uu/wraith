/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __WRAITH_H__
#define __WRAITH_H__

#define TASK_COMM_LEN 16
#define PATH_LEN 256
#define DETAIL_LEN 128

/* One value per detection rule. Kept in sync with internal/event/rules.go. */
enum wraith_signal {
	SIG_FILELESS_EXEC = 1,
	SIG_PRELOAD_HIJACK = 2,
	SIG_PROC_MEM_WRITE = 3,
	SIG_PTRACE_INJECT = 4,
	SIG_TMPFS_EXEC = 5,
	SIG_MEMFD_CREATE = 6,
};

/* Field order is chosen so the struct has no padding on amd64/arm64. */
struct event {
	__u64 ts_ns;
	__u64 aux;
	__u32 signal;
	__u32 pid;
	__u32 tid;
	__u32 ppid;
	__u32 uid;
	__u32 target_pid;
	__u8 comm[TASK_COMM_LEN];
	__u8 path[PATH_LEN];
	__u8 detail[DETAIL_LEN];
};

struct wraith_cfg {
	__u32 self_pid;
	__u32 emit_info;
};

enum wraith_stat {
	STAT_EMITTED = 0,
	STAT_DROPPED = 1,
	STAT_MAX = 2,
};

#endif /* __WRAITH_H__ */
