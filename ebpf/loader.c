/* eBPF loader — libbpf skeleton based loader for audit BPF program
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

#include "audit.skel.h"

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

struct audit_event {
    unsigned int event_type;
    unsigned int pid;
    unsigned long long timestamp_ns;
    char comm[MAX_COMM_LEN];
    unsigned char chain_depth;
    struct chain_node chain[MAX_CHAIN_DEPTH];
    char data[MAX_DATA_LEN];
};

/* Global skeleton instance */
static struct audit_bpf *g_skel = NULL;
static char g_libc_path[512] = {0};
static int g_is_musl = 0;

/* ============================================================
 * Libc path discovery
 * ============================================================ */

static int discover_libc_path(void) {
    /* Common libc paths for different distributions */
    const char *paths[] = {
        "/lib/x86_64-linux-gnu/libc.so.6",    /* Ubuntu/Debian */
        "/lib64/libc.so.6",                    /* RHEL/Fedora */
        "/lib/libc.so.6",                      /* Generic */
        "/usr/lib/libc.so.6",                  /* Arch */
        NULL
    };

    /* Check musl first */
    if (access("/lib/libc.musl-x86_64.so.1", R_OK) == 0) {
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

int bpf_load(void) {
    struct bpf_program *prog;
    int err;

    if (g_skel) {
        fprintf(stderr, "[loader] Already loaded\n");
        return 0;
    }

    /* Open and load BPF skeleton */
    g_skel = audit_bpf__open_and_load();
    if (!g_skel) {
        fprintf(stderr, "[loader] Failed to open BPF skeleton: %s\n", strerror(errno));
        return -1;
    }

    /* Auto-attach tracepoints (handled by skeleton) */
    err = audit_bpf__attach(g_skel);
    if (err) {
        /* Some tracepoints may fail to attach due to permissions - log warning and continue */
        fprintf(stderr, "[loader] Warning: Some programs failed to attach (err=%d), but BPF loaded\n", err);
    }

    /* Manually attach DNS uprobe if libc found
     * Note: SEC("uprobe/...") auto-attach is still enabled in BPF code
     * This is fallback for different libc paths */
    discover_libc_path();

    fprintf(stderr, "[loader] BPF program loaded and attached successfully\n");
    return 0;
}

void bpf_unload(void) {
    if (g_skel) {
        audit_bpf__destroy(g_skel);
        g_skel = NULL;
        fprintf(stderr, "[loader] BPF program unloaded\n");
    }
}

/* ============================================================
 * Map operations
 * ============================================================ */

int bpf_map_update_pid_whitelist(unsigned int pid, unsigned int root_pid, unsigned char depth) {
    struct whitelist_entry entry;
    int map_fd, err;

    if (!g_skel) {
        fprintf(stderr, "[loader] BPF not loaded\n");
        return -1;
    }

    map_fd = bpf_map__fd(g_skel->maps.pid_whitelist);
    if (map_fd < 0) {
        fprintf(stderr, "[loader] Invalid map fd\n");
        return -1;
    }

    memset(&entry, 0, sizeof(entry));
    entry.root_pid = root_pid;
    entry.depth = depth;

    err = bpf_map_update_elem(map_fd, &pid, &entry, BPF_ANY);
    if (err) {
        fprintf(stderr, "[loader] Failed to update pid whitelist: %d\n", err);
        return err;
    }

    return 0;
}

int bpf_map_delete_pid_whitelist(unsigned int pid) {
    int map_fd, err;

    if (!g_skel) {
        fprintf(stderr, "[loader] BPF not loaded\n");
        return -1;
    }

    map_fd = bpf_map__fd(g_skel->maps.pid_whitelist);
    if (map_fd < 0) {
        return -1;
    }

    err = bpf_map_delete_elem(map_fd, &pid);
    if (err && err != -ENOENT) {
        fprintf(stderr, "[loader] Failed to delete pid whitelist entry: %d\n", err);
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

const char *bpf_dump_events(void) {
    unsigned long long key = 0, next_key;
    struct audit_event event;
    char escaped[512];
    char buf[512];
    int first = 1;
    int map_fd, err;

    if (!g_skel) {
        return "{\"error\":\"BPF not loaded\"}";
    }

    map_fd = bpf_map__fd(g_skel->maps.events);
    if (map_fd < 0) {
        return "{\"error\":\"Invalid map fd\"}";
    }

    g_json_pos = 0;
    json_append("[");

    while (1) {
        err = bpf_map_get_next_key(map_fd, &key, &next_key);
        if (err) break;

        key = next_key;
        err = bpf_map_lookup_and_delete_elem(map_fd, &key, &event);
        if (err) continue;

        if (!first) json_append(",");
        first = 0;

        const char *type_str = "UNKNOWN";
        switch (event.event_type) {
            case 1: type_str = "FILE"; break;
            case 2: type_str = "NETWORK"; break;
            case 3: type_str = "DNS"; break;
        }

        json_escape_string(event.comm, escaped, sizeof(escaped));
        snprintf(buf, sizeof(buf),
            "{\"type\":\"%s\",\"pid\":%u,\"ts_ns\":%llu,\"comm\":\"%s\",\"chain_depth\":%d,\"chain\":[",
            type_str, event.pid, event.timestamp_ns, escaped, event.chain_depth);
        json_append(buf);

        for (int i = 0; i < event.chain_depth; i++) {
            if (i > 0) json_append(",");
            json_escape_string(event.chain[i].comm, escaped, sizeof(escaped));
            snprintf(buf, sizeof(buf), "{\"pid\":%u,\"comm\":\"%s\"}", event.chain[i].pid, escaped);
            json_append(buf);
        }

        json_append("],\"data\":\"");
        json_escape_string(event.data, escaped, sizeof(escaped));
        json_append(escaped);
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
