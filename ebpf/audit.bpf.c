/* SPDX-License-Identifier: GPL-2.0 */
/* eBPF audit program — kernel-level PID whitelist filtering with process chain tracking
 *
 * Monitors:
 *   sys_enter_openat    -> FILE open events
 *   sys_enter_read      -> FILE read events
 *   sys_enter_write     -> FILE write events
 *   sys_enter_connect   -> NET connect events
 *   getaddrinfo uprobe  -> DNS events
 *
 * Kernel-space filters by PID whitelist and packs complete process chain.
 */

#include "vmlinux.h"
#include "bpf_helpers.h"
#include "bpf_tracing.h"

#define MAX_COMM_LEN      16
#define MAX_DATA_LEN      256
#define MAX_CHAIN_DEPTH   8

enum { EVENT_TYPE_FILE = 1, EVENT_TYPE_NETWORK = 2, EVENT_TYPE_DNS = 3, EVENT_TYPE_FORK = 4 };

enum {
    ACTION_OPEN = 0, ACTION_READ = 1, ACTION_WRITE = 2,
    ACTION_CONNECT = 3,
    ACTION_RESOLVE = 4,
    ACTION_FORK = 5
};

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

struct audit_event {
    __u32 event_type;
    __u32 action_type;
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
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct audit_event);
} event_scratch SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 64);
    __uint(key_size, MAX_COMM_LEN);
    __uint(value_size, 1);
} target_comms SEC(".maps");

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

    /* Step 0: current process — use event->comm (real comm after exec) */
    event->chain[0].pid = current_pid;
    bpf_probe_read_kernel(event->chain[0].comm, MAX_COMM_LEN, event->comm);
    depth++;
    if (current_pid == entry->root_pid) goto done;

    /* Get parent pid from agent_tree for current process */
    node = bpf_map_lookup_elem(&agent_tree, &current_pid);
    if (!node) goto done;
    current_pid = node->parent_pid;

    /* Steps 1-7: ancestors from agent_tree (comm recorded at fork time) */
#define CHAIN_STEP(idx) \
    node = bpf_map_lookup_elem(&agent_tree, &current_pid); \
    if (!node) goto done; \
    event->chain[idx].pid = current_pid; \
    bpf_probe_read_kernel(event->chain[idx].comm, MAX_COMM_LEN, node->comm); \
    depth++; \
    if (current_pid == entry->root_pid) goto done; \
    current_pid = node->parent_pid;

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
    event->action_type = ACTION_OPEN;
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
    event->action_type  = ACTION_CONNECT;
    event->pid          = pid;
    event->timestamp_ns = bpf_ktime_get_ns();
    bpf_get_current_comm(event->comm, MAX_COMM_LEN);
    pack_process_chain(pid, entry, event);

    bpf_probe_read_user(event->data, 32, ctx->addr);

    bpf_map_update_elem(&events, &event->timestamp_ns, event, 0);
    return 0;
}

/* DNS uprobe — intercepts getaddrinfo() in glibc
 * Uses bpf_probe_read_kernel to extract args from pt_regs (uprobe context)
 *
 * Section format: uprobe/<path>:<symbol> — libbpf auto-attaches based on section name
 */

#if defined(__TARGET_ARCH_arm64)
SEC("uprobe//lib/aarch64-linux-gnu/libc.so.6:getaddrinfo")
#else
SEC("uprobe//lib/x86_64-linux-gnu/libc.so.6:getaddrinfo")
#endif
int trace_getaddrinfo(struct pt_regs *ctx)
{
    __u32 pid = bpf_get_current_pid_tgid() >> 32;

    struct whitelist_entry *entry = bpf_map_lookup_elem(&pid_whitelist, &pid);
    if (!entry) return 0;

    __u32 scratch_key = 0;
    struct audit_event *event = bpf_map_lookup_elem(&event_scratch, &scratch_key);
    if (!event) return 0;

    event->event_type   = EVENT_TYPE_DNS;
    event->action_type  = ACTION_RESOLVE;
    event->pid          = pid;
    event->timestamp_ns = bpf_ktime_get_ns();
    bpf_get_current_comm(event->comm, MAX_COMM_LEN);
    pack_process_chain(pid, entry, event);

    /* getaddrinfo first arg (node) - architecture specific */
    const char *node;
#if defined(__TARGET_ARCH_arm64)
    /* ARM64: x0 register is at offset 0 in struct user_pt_regs */
    bpf_probe_read_kernel(&node, sizeof(node), (void *)ctx + 0);
#else
    /* x86_64: first arg (node) in di register, offset 112 bytes */
    bpf_probe_read_kernel(&node, sizeof(node), (void *)ctx + 112);
#endif
    bpf_probe_read_user_str(event->data, MAX_DATA_LEN, node);

    bpf_map_update_elem(&events, &event->timestamp_ns, event, 0);
    return 0;
}

/* ── High-frequency syscall handlers (Phase 3) ────────────────────────── */

struct sys_enter_rw_ctx {
    unsigned char pad[16];   // common(8) + __syscall_nr(4) + pad(4)
    int fd;                  // offset 16
    char *buf;               // offset 24
    size_t count;            // offset 32
};

static __always_inline int handle_rw_event(struct sys_enter_rw_ctx *ctx, __u32 action_type) {
    __u32 pid = bpf_get_current_pid_tgid() >> 32;

    struct whitelist_entry *entry = bpf_map_lookup_elem(&pid_whitelist, &pid);
    if (!entry) return 0;

    __u32 zero = 0;
    struct audit_event *event = bpf_map_lookup_elem(&event_scratch, &zero);
    if (!event) return 0;

    event->event_type  = EVENT_TYPE_FILE;
    event->action_type = action_type;
    event->pid         = pid;
    event->timestamp_ns = bpf_ktime_get_ns();
    bpf_get_current_comm(event->comm, MAX_COMM_LEN);
    pack_process_chain(pid, entry, event);

    /* data = "fd=X bytes=Y" */
    {
        __u64 args[] = {(__u64)ctx->fd, (__u64)ctx->count};
        bpf_snprintf(event->data, MAX_DATA_LEN, "fd=%d bytes=%llu",
                     args, sizeof(args));
    }

    bpf_map_update_elem(&events, &event->timestamp_ns, event, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_read")
int handle_read(struct sys_enter_rw_ctx *ctx) {
    return handle_rw_event(ctx, ACTION_READ);
}

SEC("tracepoint/syscalls/sys_enter_write")
int handle_write(struct sys_enter_rw_ctx *ctx) {
    return handle_rw_event(ctx, ACTION_WRITE);
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
    struct whitelist_entry child_entry;
    __builtin_memset(&child_entry, 0, sizeof(child_entry));
    child_entry.root_pid = parent_entry->root_pid;
    child_entry.depth = parent_entry->depth + 1;
    bpf_map_update_elem(&pid_whitelist, &child_pid, &child_entry, 0);

    // Add child to agent_tree
    struct tree_node child_node;
    __builtin_memset(&child_node, 0, sizeof(child_node));
    child_node.parent_pid = parent_pid;
    child_node.fork_time = bpf_ktime_get_ns();
    bpf_get_current_comm(child_node.comm, MAX_COMM_LEN);
    bpf_map_update_elem(&agent_tree, &child_pid, &child_node, 0);

    // Emit fork event (with process chain)
    {
        __u32 zero = 0;
        struct audit_event *fev = bpf_map_lookup_elem(&event_scratch, &zero);
        if (fev) {
            __builtin_memset(fev, 0, sizeof(*fev));
            fev->event_type = EVENT_TYPE_FORK;
            fev->action_type = ACTION_FORK;
            fev->pid = child_pid;
            fev->timestamp_ns = bpf_ktime_get_ns();
            __builtin_memcpy(fev->comm, child_node.comm, MAX_COMM_LEN);

            // Pack process chain (includes parent chain)
            pack_process_chain(child_pid, &child_entry, fev);

            bpf_map_update_elem(&events, &fev->timestamp_ns, fev, 0);
        }
    }

    return 0;
}

struct sched_process_exec_ctx {
    __u32 common[2];      // common_type/flags/preempt/pid (8 bytes)
    __u32 filename_loc;   // offset 8 (data_loc, not used)
    __u32 pid;            // offset 12
};

SEC("tracepoint/sched/sched_process_exec")
int handle_sched_process_exec(struct sched_process_exec_ctx *ctx) {
    __u32 pid = ctx->pid;

    struct whitelist_entry *entry = bpf_map_lookup_elem(&pid_whitelist, &pid);
    if (entry) {
        // Already in whitelist — update comm in agent_tree
        struct tree_node *node = bpf_map_lookup_elem(&agent_tree, &pid);
        if (node) {
            bpf_get_current_comm(node->comm, MAX_COMM_LEN);
            bpf_map_update_elem(&agent_tree, &pid, node, 0);
        }
        return 0;
    }

    // Not in whitelist — check target_comms for exec-time matching
    char comm[MAX_COMM_LEN] = {};
    bpf_get_current_comm(comm, MAX_COMM_LEN);
    __u8 *found = bpf_map_lookup_elem(&target_comms, comm);
    if (!found) return 0;

    // Match: add to pid_whitelist as root (depth=0, root_pid=self)
    struct whitelist_entry new_entry;
    __builtin_memset(&new_entry, 0, sizeof(new_entry));
    new_entry.root_pid = pid;
    new_entry.depth = 0;
    bpf_map_update_elem(&pid_whitelist, &pid, &new_entry, 0);

    // Add to agent_tree (parent_pid=0, no parent for exec-matched root)
    struct tree_node new_node;
    __builtin_memset(&new_node, 0, sizeof(new_node));
    new_node.fork_time = bpf_ktime_get_ns();
    __builtin_memcpy(new_node.comm, comm, MAX_COMM_LEN);
    bpf_map_update_elem(&agent_tree, &pid, &new_node, 0);

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

    // Delete self from maps
    bpf_map_delete_elem(&pid_whitelist, &pid);
    bpf_map_delete_elem(&agent_tree, &pid);

    return 0;
}

char LICENSE[] SEC("license") = "GPL";
