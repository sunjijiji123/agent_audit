/* eBPF loader — libbpf loader for audit BPF program
 *
 * Provides:
 *   - BPF program load/attach/unload
 *   - Map operations: update pid whitelist, dump events
 *   - Runtime libc path discovery for DNS uprobe
 *   - Musl environment detection
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>

/* Match BPF struct definitions */
#define MAX_COMM_LEN      16
#define MAX_DATA_LEN      256
#define MAX_CHAIN_DEPTH   8

struct chain_node {
    unsigned int pid;
    char comm[MAX_COMM_LEN];
};

struct whitelist_entry {
    unsigned int root_pid;
    unsigned char depth;
};

struct tree_node {
    unsigned int parent_pid;
    char comm[16];
    unsigned long long fork_time;
};

struct audit_event {
    unsigned int event_type;
    unsigned int action_type;
    unsigned int pid;
    unsigned long long timestamp_ns;
    char comm[MAX_COMM_LEN];
    unsigned char chain_depth;
    struct chain_node chain[MAX_CHAIN_DEPTH];
    char data[MAX_DATA_LEN];
};

/* Global state */
static struct bpf_object *g_obj = NULL;
static int g_pid_whitelist_fd = -1;
static int g_agent_tree_fd = -1;
static int g_events_fd = -1;
static char g_libc_path[512] = {0};
static int g_is_musl = 0;

/* ============================================================
 * Libc path discovery
 * ============================================================ */

static int discover_libc_path(void) {
    /* Common libc paths for different distributions */
    const char *paths[] = {
        "/lib/aarch64-linux-gnu/libc.so.6",   /* Ubuntu/Debian ARM64 */
        "/lib/x86_64-linux-gnu/libc.so.6",    /* Ubuntu/Debian x86_64 */
        "/lib64/libc.so.6",                    /* RHEL/Fedora */
        "/lib/libc.so.6",                      /* Generic */
        "/usr/lib/libc.so.6",                  /* Arch */
        NULL
    };

    /* Check musl first */
    if (access("/lib/libc.musl-aarch64.so.1", R_OK) == 0) {
        g_is_musl = 1;
        fprintf(stderr, "[loader] Detected musl environment (Alpine)\n");
        return -1;  /* Musl DNS uprobe not supported yet */
    }

    /* Try each common path */
    for (int i = 0; paths[i]; i++) {
        if (access(paths[i], R_OK) == 0) {
            strncpy(g_libc_path, paths[i], sizeof(g_libc_path) - 1);
            fprintf(stderr, "[loader] Found libc at: %s\n", g_libc_path);
            return 0;
        }
    }

    /* Method 2: Use ldd to find libc path */
    FILE *f = popen("ldd /bin/sh 2>/dev/null | grep 'libc.so.6' | awk '{print $3}'", "r");
    if (f) {
        char buf[512];
        if (fgets(buf, sizeof(buf), f)) {
            buf[strcspn(buf, "\n")] = 0;
            if (strlen(buf) > 0 && access(buf, R_OK) == 0) {
                strncpy(g_libc_path, buf, sizeof(g_libc_path) - 1);
                fprintf(stderr, "[loader] Found libc via ldd: %s\n", g_libc_path);
                pclose(f);
                return 0;
            }
        }
        pclose(f);
    }

    fprintf(stderr, "[loader] Warning: Could not find libc.so.6, DNS uprobe disabled\n");
    return -1;
}

/* ============================================================
 * BPF load/attach/unload
 * ============================================================ */

/* Default BPF object path — set via bpf_set_elf_path() or use env BPF_ELF_PATH */
static char g_elf_path[512] = {0};

void bpf_set_elf_path(const char *path) {
    if (path) strncpy(g_elf_path, path, sizeof(g_elf_path) - 1);
}

int bpf_load(void) {
    struct bpf_program *prog;
    struct bpf_link *link;
    int err;

    if (g_obj) {
        fprintf(stderr, "[loader] Already loaded\n");
        return 0;
    }

    /* Open BPF object file — same as bpftool prog loadall */
    g_obj = bpf_object__open_file(g_elf_path, NULL);
    if (!g_obj) {
        fprintf(stderr, "[loader] Failed to open BPF object: %s\n", strerror(errno));
        return -1;
    }

    /* Load into kernel — triggers verifier */
    err = bpf_object__load(g_obj);
    if (err) {
        fprintf(stderr, "[loader] Failed to load BPF object: %d\n", err);
        bpf_object__close(g_obj);
        g_obj = NULL;
        return -1;
    }

    /* Auto-attach all programs */
    bpf_object__for_each_program(prog, g_obj) {
        link = bpf_program__attach(prog);
        if (!link) {
            fprintf(stderr, "[loader] Warning: failed to attach %s: %s\n",
                    bpf_program__name(prog), strerror(errno));
        } else {
            fprintf(stderr, "[loader] Attached: %s\n", bpf_program__name(prog));
        }
    }

    /* Cache map FDs */
    g_pid_whitelist_fd = bpf_object__find_map_fd_by_name(g_obj, "pid_whitelist");
    g_agent_tree_fd = bpf_object__find_map_fd_by_name(g_obj, "agent_tree");
    g_events_fd = bpf_object__find_map_fd_by_name(g_obj, "events");

    if (g_pid_whitelist_fd < 0)
        fprintf(stderr, "[loader] Warning: pid_whitelist map not found\n");
    if (g_agent_tree_fd < 0)
        fprintf(stderr, "[loader] Warning: agent_tree map not found\n");
    if (g_events_fd < 0)
        fprintf(stderr, "[loader] Warning: events map not found\n");

    /* Discover libc for DNS uprobe */
    discover_libc_path();

    fprintf(stderr, "[loader] BPF program loaded and attached successfully\n");
    return 0;
}

void bpf_unload(void) {
    if (g_obj) {
        bpf_object__close(g_obj);
        g_obj = NULL;
        g_pid_whitelist_fd = -1;
        g_agent_tree_fd = -1;
        g_events_fd = -1;
        fprintf(stderr, "[loader] BPF program unloaded\n");
    }
}

/* ============================================================
 * Map operations
 * ============================================================ */

int bpf_map_update_pid_whitelist(unsigned int pid, unsigned int root_pid, unsigned char depth) {
    struct whitelist_entry entry;
    int err;

    if (!g_obj || g_pid_whitelist_fd < 0) {
        fprintf(stderr, "[loader] BPF not loaded\n");
        return -1;
    }

    memset(&entry, 0, sizeof(entry));
    entry.root_pid = root_pid;
    entry.depth = depth;

    err = bpf_map_update_elem(g_pid_whitelist_fd, &pid, &entry, BPF_ANY);
    if (err) {
        fprintf(stderr, "[loader] Failed to update pid whitelist: %d\n", err);
        return err;
    }

    return 0;
}

int bpf_map_delete_pid_whitelist(unsigned int pid) {
    int err;

    if (!g_obj || g_pid_whitelist_fd < 0) {
        fprintf(stderr, "[loader] BPF not loaded\n");
        return -1;
    }

    err = bpf_map_delete_elem(g_pid_whitelist_fd, &pid);
    if (err && err != -ENOENT) {
        fprintf(stderr, "[loader] Failed to delete pid whitelist entry: %d\n", err);
        return err;
    }

    return 0;
}

int bpf_map_update_agent_tree(unsigned int pid, const char *comm) {
    struct tree_node node;
    int err;

    if (!g_obj || g_agent_tree_fd < 0) {
        fprintf(stderr, "[loader] BPF not loaded or agent_tree not found\n");
        return -1;
    }

    memset(&node, 0, sizeof(node));
    node.parent_pid = pid;  /* root: parent_pid = self */
    if (comm) strncpy(node.comm, comm, sizeof(node.comm) - 1);

    err = bpf_map_update_elem(g_agent_tree_fd, &pid, &node, BPF_ANY);
    if (err) {
        fprintf(stderr, "[loader] Failed to update agent_tree: %d\n", err);
        return err;
    }

    return 0;
}

/* ============================================================
 * Events dump
 * ============================================================ */

/* Simple JSON buffer for events dump */
static char g_json_buf[256 * 1024];
static int g_json_pos = 0;

static void json_append(const char *str) {
    int len = strlen(str);
    if (g_json_pos + len < (int)sizeof(g_json_buf) - 1) {
        strcpy(g_json_buf + g_json_pos, str);
        g_json_pos += len;
    }
}

static void json_escape_string(const char *str, char *out, int out_size) {
    int j = 0;
    for (int i = 0; str[i] && j < out_size - 1; i++) {
        if (str[i] == '"' || str[i] == '\\') {
            out[j++] = '\\';
        }
        if (str[i] >= 32 && str[i] < 127) {
            out[j++] = str[i];
        }
    }
    out[j] = 0;
}

/* Parse raw sockaddr bytes into readable string.
 * Handles AF_INET (IPv4) and AF_INET6 (IPv6). */
static void _format_sockaddr(const char *data, char *out, int out_size) {
    if (!data || out_size < 16) {
        snprintf(out, out_size, "(empty)");
        return;
    }

    unsigned short family = *(const unsigned short *)data;

    if (family == 2) { /* AF_INET */
        unsigned short port = *(const unsigned short *)(data + 2);
        port = ((port & 0xff) << 8) | ((port >> 8) & 0xff); /* ntohs */
        const unsigned char *addr = (const unsigned char *)(data + 4);
        snprintf(out, out_size, "AF_INET %u.%u.%u.%u:%u",
                 addr[0], addr[1], addr[2], addr[3], port);
    } else if (family == 10) { /* AF_INET6 */
        unsigned short port = *(const unsigned short *)(data + 2);
        port = ((port & 0xff) << 8) | ((port >> 8) & 0xff); /* ntohs */
        const unsigned char *addr = (const unsigned char *)(data + 8);
        snprintf(out, out_size, "AF_INET6 [%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x]:%u",
                 addr[0], addr[1], addr[2], addr[3], addr[4], addr[5], addr[6], addr[7],
                 addr[8], addr[9], addr[10], addr[11], addr[12], addr[13], addr[14], addr[15],
                 port);
    } else {
        snprintf(out, out_size, "family=%u (raw)", family);
    }
}

const char *bpf_dump_events(void) {
    unsigned long long key = 0, next_key;
    struct audit_event event;
    char escaped[512];
    char buf[512];
    int first = 1;
    int err;

    if (!g_obj || g_events_fd < 0) {
        return "{\"error\":\"BPF not loaded\"}";
    }

    g_json_pos = 0;
    json_append("[");

    while (1) {
        err = bpf_map_get_next_key(g_events_fd, &key, &next_key);
        if (err) break;

        key = next_key;
        err = bpf_map_lookup_and_delete_elem(g_events_fd, &key, &event);
        if (err) continue;

        if (!first) json_append(",");
        first = 0;

        const char *type_str = "UNKNOWN";
        switch (event.event_type) {
            case 1: type_str = "FILE"; break;
            case 2: type_str = "NET"; break;
            case 3: type_str = "DNS"; break;
            case 4: type_str = "FORK"; break;
        }

        const char *action_str = "unknown";
        switch (event.action_type) {
            case 0: action_str = "open"; break;
            case 1: action_str = "read"; break;
            case 2: action_str = "write"; break;
            case 3: action_str = "connect"; break;
            case 4: action_str = "send"; break;
            case 5: action_str = "recv"; break;
            case 6: action_str = "resolve"; break;
            case 5: action_str = "fork"; break;
        }

        json_escape_string(event.comm, escaped, sizeof(escaped));
        snprintf(buf, sizeof(buf),
            "{\"type\":\"%s\",\"action\":\"%s\",\"pid\":%u,\"ts_ns\":%llu,\"comm\":\"%s\",\"chain_depth\":%d,\"chain\":[",
            type_str, action_str, event.pid, event.timestamp_ns, escaped, event.chain_depth);
        json_append(buf);

        for (int i = 0; i < event.chain_depth; i++) {
            if (i > 0) json_append(",");
            json_escape_string(event.chain[i].comm, escaped, sizeof(escaped));
            snprintf(buf, sizeof(buf), "{\"pid\":%u,\"comm\":\"%s\"}", event.chain[i].pid, escaped);
            json_append(buf);
        }

        json_append("],\"data\":\"");
        if (event.event_type == 2 && event.action_type == 3) {
            /* NET connect: data is raw sockaddr — parse to readable string */
            _format_sockaddr(event.data, buf, sizeof(buf));
            json_append(buf);
        } else {
            /* FILE/DNS/send/recv events: data is already a formatted string */
            json_escape_string(event.data, escaped, sizeof(escaped));
            json_append(escaped);
        }
        json_append("\"}");
    }

    json_append("]");
    return g_json_buf;
}

/* ============================================================
 * Main (for standalone testing)
 * ============================================================ */

#ifdef LOADER_MAIN
int main(int argc, char *argv[]) {
    if (bpf_load() != 0) {
        return 1;
    }

    printf("BPF loaded. Events:\n");
    while (1) {
        const char *events = bpf_dump_events();
        if (strlen(events) > 2) {  /* Not just "[]" */
            printf("%s\n", events);
        }
        sleep(1);
    }

    bpf_unload();
    return 0;
}
#endif
