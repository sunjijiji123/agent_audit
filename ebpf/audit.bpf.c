/* SPDX-License-Identifier: GPL-2.0 */
/* eBPF audit program — kernel-level comm whitelist filtering
 *
 * Monitors:
 *   sys_enter_openat    -> FILE events
 *   sys_enter_connect   -> NET events
 *   getaddrinfo uprobe  -> DNS events
 *
 * Kernel-space filters by process comm whitelist to reduce noise.
 */

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

#define MAX_COMM_LEN  16
#define MAX_DATA_LEN  256

enum { EVENT_TYPE_FILE = 1, EVENT_TYPE_NETWORK = 2, EVENT_TYPE_DNS = 3 };

struct audit_event {
    __u32 event_type;
    __u32 pid;
    __u64 timestamp_ns;
    char comm[MAX_COMM_LEN];
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
    __uint(max_entries, 256);
    __type(key, char[MAX_COMM_LEN]);
    __type(value, __u32);
} comm_whitelist SEC(".maps");

struct sys_enter_ctx {
    __u64 __unused;
    long id;
    unsigned long args[6];
};

static __always_inline __u16 __bpf_ntohs(__u16 x) {
    return (__u16)(((x & 0xff) << 8) | ((x >> 8) & 0xff));
}

SEC("tracepoint/syscalls/sys_enter_openat")
int handle_openat(struct sys_enter_ctx *ctx) {
    char comm[MAX_COMM_LEN];
    bpf_get_current_comm(comm, MAX_COMM_LEN);

    __u32 *allowed = bpf_map_lookup_elem(&comm_whitelist, comm);
    if (!allowed) return 0;

    struct audit_event event = {};
    event.event_type   = EVENT_TYPE_FILE;
    event.pid          = bpf_get_current_pid_tgid() >> 32;
    event.timestamp_ns = bpf_ktime_get_ns();
    bpf_get_current_comm(event.comm, MAX_COMM_LEN);
    bpf_probe_read_user_str(event.data, MAX_DATA_LEN, (const void *)ctx->args[1]);
    bpf_map_update_elem(&events, &event.timestamp_ns, &event, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_connect")
int handle_connect(struct sys_enter_ctx *ctx) {
    char comm[MAX_COMM_LEN];
    bpf_get_current_comm(comm, MAX_COMM_LEN);

    __u32 *allowed = bpf_map_lookup_elem(&comm_whitelist, comm);
    if (!allowed) return 0;

    struct audit_event event = {};
    event.event_type   = EVENT_TYPE_NETWORK;
    event.pid          = bpf_get_current_pid_tgid() >> 32;
    event.timestamp_ns = bpf_ktime_get_ns();
    bpf_get_current_comm(event.comm, MAX_COMM_LEN);

    const void *addr = (const void *)ctx->args[1];
    bpf_probe_read(event.data, 16, addr);

    bpf_map_update_elem(&events, &event.timestamp_ns, &event, 0);
    return 0;
}

/* DNS uprobe — intercepts getaddrinfo() in glibc
 * Define pt_regs before bpf_tracing.h so BPF_KPROBE macros work. */
struct pt_regs {
    unsigned long r15, r14, r13, r12, rbp, rbx;
    unsigned long r11, r10, r9, r8, rax, rcx, rdx, rsi, rdi, orig_rax;
    unsigned long rip, cs, eflags, rsp, ss;
};

#include <bpf/bpf_tracing.h>

SEC("uprobe/lib/x86_64-linux-gnu/libc.so.6:getaddrinfo")
int BPF_KPROBE(trace_getaddrinfo, const char *node, const char *service)
{
    char comm[MAX_COMM_LEN];
    bpf_get_current_comm(comm, MAX_COMM_LEN);

    __u32 *allowed = bpf_map_lookup_elem(&comm_whitelist, comm);
    if (!allowed) return 0;

    struct audit_event event = {};
    event.event_type   = EVENT_TYPE_DNS;
    event.pid          = bpf_get_current_pid_tgid() >> 32;
    event.timestamp_ns = bpf_ktime_get_ns();
    bpf_get_current_comm(event.comm, MAX_COMM_LEN);
    bpf_probe_read_user_str(event.data, MAX_DATA_LEN, node);
    bpf_map_update_elem(&events, &event.timestamp_ns, &event, 0);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
