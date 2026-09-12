/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __VMLINUX_H__
#define __VMLINUX_H__

/*
 * Minimal hand-rolled vmlinux.h.
 *
 * Only the types wraith actually touches are declared. CO-RE resolves every
 * field offset from the running kernel's BTF at load time, so a partial
 * declaration is enough and keeps the tree free of a 3 MB generated header.
 * Regenerate the full one with `bpftool btf dump file /sys/kernel/btf/vmlinux
 * format c` if a new probe needs types that are not here.
 */

#ifndef __KERNEL_TYPES__
#define __KERNEL_TYPES__
typedef signed char __s8;
typedef unsigned char __u8;
typedef short int __s16;
typedef short unsigned int __u16;
typedef int __s32;
typedef unsigned int __u32;
typedef long long int __s64;
typedef long long unsigned int __u64;
typedef __u8 u8;
typedef __u16 u16;
typedef __u32 u32;
typedef __u64 u64;
typedef __s32 s32;
typedef __s64 s64;
typedef int pid_t;

typedef __u16 __be16;
typedef __u16 __le16;
typedef __u32 __be32;
typedef __u32 __le32;
typedef __u64 __be64;
typedef __u64 __le64;
typedef __u16 __sum16;
typedef __u32 __wsum;
#endif

/*
 * UAPI constants normally supplied by the generated vmlinux.h. Values are
 * fixed by the kernel ABI; only the ones wraith uses are listed.
 */
enum bpf_map_type {
	BPF_MAP_TYPE_ARRAY = 2,
	BPF_MAP_TYPE_PERCPU_ARRAY = 6,
	BPF_MAP_TYPE_LRU_HASH = 9,
	BPF_MAP_TYPE_RINGBUF = 27,
};

enum {
	BPF_ANY = 0,
	BPF_NOEXIST = 1,
	BPF_EXIST = 2,
};

#ifndef BPF_NO_PRESERVE_ACCESS_INDEX
#pragma clang attribute push(__attribute__((preserve_access_index)), apply_to = record)
#endif

struct trace_entry {
	short unsigned int type;
	unsigned char flags;
	unsigned char preempt_count;
	int pid;
};

struct trace_event_raw_sys_enter {
	struct trace_entry ent;
	long int id;
	long unsigned int args[6];
	char __data[0];
};

struct task_struct {
	int pid;
	int tgid;
	struct task_struct *real_parent;
	struct task_struct *group_leader;
};

#ifndef BPF_NO_PRESERVE_ACCESS_INDEX
#pragma clang attribute pop
#endif

#endif /* __VMLINUX_H__ */
