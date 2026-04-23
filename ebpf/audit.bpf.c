/* SPDX-License-Identifier: GPL-2.0 */
/* eBPF audit program — kernel-level PID whitelist filtering with process chain tracking
 *
 * Monitors:
 *   sys_enter_openat    -> FILE events
 *   sys_enter_connect   -> NET events
 *   getaddrinfo uprobe  -> DNS events
 *
 * Kernel-space filters by PID whitelist and packs complete process chain.
 */

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#define MAX_COMM_LEN      16
#define MAX_DATA_LEN      256
#define MAX_CHAIN_DEPTH   8
#define MAX_CHILDREN      16

enum { EVENT_TYPE_FILE = 1, EVENT_TYPE_NETWORK = 2, EVENT_TYPE_DNS = 3 };

struct chain_node {
    __u32 pid;
    char comm[MAX_COMM_LEN];
};

struct whitelist_entry {
    __u32 root_pid;  // Agent root process PID
    __u8  depth;     // Process tree depth (0=root, 1=child, 2=grandchild...)
};

struct tree_node {
    __u32 parent_pid;
    char comm[MAX_COMM_LEN];
    __u64 fork_time;
};

struct children_list {
    __u32 child_pids[MAX_CHILDREN];
    __u8  count;
};

struct audit_event {
    __u32 event_type;
    __u32 pid;
    __u64 timestamp_ns;
    char comm[MAX_COMM_LEN];
    __u8  chain_depth;
    struct chain_node chain[MAX_CHAIN_DEPTH];
    char data[MAX_DATA_LEN];
};

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 65536);
    __uint(key_size, 8);
    __uint(value_size, sizeof(struct audit_event));
} events SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __u32);
    __type(value, struct whitelist_entry);
} pid_whitelist SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 2048);
    __type(key, __u32);
    __type(value, struct tree_node);
} agent_tree SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 2048);
    __type(key, __u32);
    __type(value, struct children_list);
} agent_children SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct audit_event);
} event_scratch SEC(".maps");

struct sys_enter_openat_ctx {
    unsigned char pad[24];   // common fields + __syscall_nr + dfd
    const char *filename;
};

struct sys_enter_connect_ctx {
    unsigned char pad[24];   // common fields + __syscall_nr + fd
    void *addr;
};

static __always_inline __u16 __bpf_ntohs(__u16 x) {
    return (__u16)(((x & 0xff) << 8) | ((x >> 8) & 0xff));
}

static __always_inline void pack_process_chain(__u32 pid, struct whitelist_entry *entry, struct audit_event *event) {
    __u32 current_pid = pid;
    __u32 depth = 0;
    struct tree_node *node;

    /* Manually unrolled — BPF verifier cannot track loop index bounds */
#define CHAIN_STEP(idx) \
    node = bpf_map_lookup_elem(&agent_tree, &current_pid); \
    if (!node) goto done; \
    event->chain[idx].pid = current_pid; \
    bpf_probe_read_kernel(event->chain[idx].comm, MAX_COMM_LEN, node->comm); \
    depth++; \
    if (current_pid == entry->root_pid) goto done; \
    current_pid = node->parent_pid;

    CHAIN_STEP(0)
    CHAIN_STEP(1)
    CHAIN_STEP(2)
    CHAIN_STEP(3)
    CHAIN_STEP(4)
    CHAIN_STEP(5)
    CHAIN_STEP(6)
    CHAIN_STEP(7)

#undef CHAIN_STEP

done:
    event->chain_depth = (__u8)depth;
}

SEC("tracepoint/syscalls/sys_enter_openat")
int handle_openat(struct sys_enter_openat_ctx *ctx) {
    __u32 pid = bpf_get_current_pid_tgid() >> 32;

    struct whitelist_entry *entry = bpf_map_lookup_elem(&pid_whitelist, &pid);
    if (!entry) return 0;

    __u32 zero = 0;
    struct audit_event *event = bpf_map_lookup_elem(&event_scratch, &zero);
    if (!event) return 0;

    event->event_type = EVENT_TYPE_FILE;
    event->pid = pid;
    event->timestamp_ns = bpf_ktime_get_ns();
    bpf_get_current_comm(event->comm, MAX_COMM_LEN);
    pack_process_chain(pid, entry, event);
    bpf_probe_read_user_str(event->data, MAX_DATA_LEN, ctx->filename);

    bpf_map_update_elem(&events, &event->timestamp_ns, event, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_connect")
int handle_connect(struct sys_enter_connect_ctx *ctx) {
    __u32 pid = bpf_get_current_pid_tgid() >> 32;

    struct whitelist_entry *entry = bpf_map_lookup_elem(&pid_whitelist, &pid);
    if (!entry) return 0;

    __u32 scratch_key = 0;
    struct audit_event *event = bpf_map_lookup_elem(&event_scratch, &scratch_key);
    if (!event) return 0;

    event->event_type   = EVENT_TYPE_NETWORK;
    event->pid          = pid;
    event->timestamp_ns = bpf_ktime_get_ns();
    bpf_get_current_comm(event->comm, MAX_COMM_LEN);
    pack_process_chain(pid, entry, event);

    bpf_probe_read_user(event->data, 32, ctx->addr);

    bpf_map_update_elem(&events, &event->timestamp_ns, event, 0);
    return 0;
}

/* DNS uprobe — intercepts getaddrinfo() in glibc
 * pt_regs from vmlinux.h, BPF_KPROBE from bpf_tracing.h */

SEC("uprobe//lib/x86_64-linux-gnu/libc.so.6:getaddrinfo")
int BPF_KPROBE(trace_getaddrinfo, const char *node, const char *service)
{
    __u32 pid = bpf_get_current_pid_tgid() >> 32;

    struct whitelist_entry *entry = bpf_map_lookup_elem(&pid_whitelist, &pid);
    if (!entry) return 0;

    __u32 scratch_key = 0;
    struct audit_event *event = bpf_map_lookup_elem(&event_scratch, &scratch_key);
    if (!event) return 0;

    event->event_type   = EVENT_TYPE_DNS;
    event->pid          = pid;
    event->timestamp_ns = bpf_ktime_get_ns();
    bpf_get_current_comm(event->comm, MAX_COMM_LEN);
    pack_process_chain(pid, entry, event);
    bpf_probe_read_user_str(event->data, MAX_DATA_LEN, node);
    bpf_map_update_elem(&events, &event->timestamp_ns, event, 0);
    return 0;
}

/* Tracepoint handlers for process lifecycle management */

struct sched_process_fork_ctx {
    __u64 __unused;
    char parent_comm[16];
    __u32 parent_pid;
    char child_comm[16];
    __u32 child_pid;
};

SEC("tracepoint/sched/sched_process_fork")
int handle_sched_process_fork(struct sched_process_fork_ctx *ctx) {
    __u32 parent_pid = ctx->parent_pid;
    __u32 child_pid = ctx->child_pid;

    struct whitelist_entry *parent_entry = bpf_map_lookup_elem(&pid_whitelist, &parent_pid);
    if (!parent_entry) return 0;  // Parent not in whitelist, skip

    // Add child to whitelist (same root_pid, depth+1)
    struct whitelist_entry child_entry = {
        .root_pid = parent_entry->root_pid,
        .depth = parent_entry->depth + 1
    };
    bpf_map_update_elem(&pid_whitelist, &child_pid, &child_entry, 0);

    // Add child to agent_tree
    struct tree_node child_node = {
        .parent_pid = parent_pid,
        .fork_time = bpf_ktime_get_ns()
    };
    bpf_get_current_comm(child_node.comm, MAX_COMM_LEN);
    bpf_map_update_elem(&agent_tree, &child_pid, &child_node, 0);

    // Add child to parent's children list
    struct children_list *children = bpf_map_lookup_elem(&agent_children, &parent_pid);
    if (children && children->count < MAX_CHILDREN) {
        children->child_pids[children->count] = child_pid;
        children->count++;
        bpf_map_update_elem(&agent_children, &parent_pid, children, 0);
    }

    return 0;
}

struct sched_process_exec_ctx {
    __u64 __unused;
    char comm[16];
    __u32 pid;
};

SEC("tracepoint/sched/sched_process_exec")
int handle_sched_process_exec(struct sched_process_exec_ctx *ctx) {
    __u32 pid = ctx->pid;

    struct whitelist_entry *entry = bpf_map_lookup_elem(&pid_whitelist, &pid);
    if (!entry) return 0;  // Not in whitelist, skip

    struct tree_node *node = bpf_map_lookup_elem(&agent_tree, &pid);
    if (node) {
        bpf_probe_read_kernel(node->comm, MAX_COMM_LEN, ctx->comm);
        bpf_map_update_elem(&agent_tree, &pid, node, 0);
    }

    return 0;
}

struct sched_process_exit_ctx {
    __u64 __unused;
    char comm[16];
    __u32 pid;
};

SEC("tracepoint/sched/sched_process_exit")
int handle_sched_process_exit(struct sched_process_exit_ctx *ctx) {
    __u32 pid = ctx->pid;

    struct whitelist_entry *entry = bpf_map_lookup_elem(&pid_whitelist, &pid);
    if (!entry) return 0;  // Not in whitelist, skip

    // Recursive cleanup: delete all children first
    struct children_list *children = bpf_map_lookup_elem(&agent_children, &pid);
    if (children) {
        for (int i = 0; i < MAX_CHILDREN && i < children->count; i++) {
            __u32 child_pid = children->child_pids[i];
            bpf_map_delete_elem(&pid_whitelist, &child_pid);
            bpf_map_delete_elem(&agent_tree, &child_pid);
            bpf_map_delete_elem(&agent_children, &child_pid);
        }
    }

    // Delete self
    bpf_map_delete_elem(&pid_whitelist, &pid);
    bpf_map_delete_elem(&agent_tree, &pid);
    bpf_map_delete_elem(&agent_children, &pid);

    return 0;
}

char LICENSE[] SEC("license") = "GPL";
