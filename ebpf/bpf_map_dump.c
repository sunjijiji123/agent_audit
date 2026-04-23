/* Fast BPF map reader — outputs JSON lines to stdout.
 * Usage: bpf_map_dump <map_id>
 * Output: one JSON object per line
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <linux/bpf.h>
#include <errno.h>

#ifndef __NR_bpf
#define __NR_bpf 321
#endif

#define MAX_COMM  16
#define MAX_DATA  256
#define MAX_CHAIN_DEPTH 8

struct chain_node {
    __u32 pid;
    char comm[MAX_COMM];
};

struct audit_event {
    __u32 event_type;
    __u32 pid;
    __u64 timestamp_ns;
    char comm[MAX_COMM];
    __u8 chain_depth;
    struct chain_node chain[MAX_CHAIN_DEPTH];
    char data[MAX_DATA];
};

static int bpf_map_lookup_elem(int map_fd, const void *key, void *value)
{
    union bpf_attr attr = {};
    attr.map_fd = map_fd;
    attr.key = (__u64)(unsigned long)key;
    attr.value = (__u64)(unsigned long)value;
    return syscall(__NR_bpf, BPF_MAP_LOOKUP_ELEM, &attr, sizeof(attr));
}

static int bpf_map_get_next_key(int map_fd, const void *key, void *next_key)
{
    union bpf_attr attr = {};
    attr.map_fd = map_fd;
    attr.key = (__u64)(unsigned long)key;
    attr.next_key = (__u64)(unsigned long)next_key;
    return syscall(__NR_bpf, BPF_MAP_GET_NEXT_KEY, &attr, sizeof(attr));
}

static void json_write_str(char *out, const char *in, int maxlen)
{
    int j = 0;
    out[j++] = '"';
    for (int i = 0; i < maxlen && in[i]; i++) {
        unsigned char c = (unsigned char)in[i];
        if (c == '"' || c == '\\' || c == '/') {
            out[j++] = '\\';
        }
        if (c >= 0x20 && c < 0x7f) {
            out[j++] = (char)c;
        } else {
            j += sprintf(out + j, "\\u%04x", c);
        }
    }
    out[j++] = '"';
    out[j] = '\0';
}

int main(int argc, char **argv)
{
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <map_id>\n", argv[0]);
        return 1;
    }

    int map_id = atoi(argv[1]);

    union bpf_attr attr = {};
    attr.map_id = map_id;
    int map_fd = syscall(__NR_bpf, BPF_MAP_GET_FD_BY_ID, &attr, sizeof(attr));
    if (map_fd < 0) {
        fprintf(stderr, "map %d not found\n", map_id);
        return 1;
    }

    __u64 key = 0;
    __u64 next_key = 0;
    struct audit_event value;
    int count = 0;
    char esc[MAX_DATA * 6 + 4];

    if (bpf_map_get_next_key(map_fd, NULL, &next_key) < 0) {
        close(map_fd);
        return 0;
    }

    while (1) {
        key = next_key;
        if (bpf_map_lookup_elem(map_fd, &key, &value) == 0) {
            const char *ts;
            switch (value.event_type) {
                case 1: ts = "FILE"; break;
                case 2: ts = "NET";  break;
                case 3: ts = "DNS";  break;
                default: ts = "UNKNOWN"; break;
            }

            // Build JSON output
            printf("{\"type\":\"%s\",\"pid\":%u,\"ts_ns\":%lu,\"comm\":\"%s\",\"chain_depth\":%u,\"chain\":[",
                   ts, value.pid, (unsigned long)value.timestamp_ns,
                   value.comm, value.chain_depth);

            // Output chain nodes
            for (int i = 0; i < value.chain_depth && i < MAX_CHAIN_DEPTH; i++) {
                if (i > 0) printf(",");
                printf("{\"pid\":%u,\"comm\":\"%s\"}",
                       value.chain[i].pid, value.chain[i].comm);
            }

            printf("],\"data\":");

            if (value.event_type == 2) {
                /* NET: parse raw sockaddr into IP:port */
                unsigned char *sa = (unsigned char *)value.data;
                unsigned short family = *(unsigned short *)sa;
                if (family == 2) {
                    unsigned char ip0 = sa[4], ip1 = sa[5], ip2 = sa[6], ip3 = sa[7];
                    unsigned short port = ((unsigned short)sa[2] << 8) | sa[3];
                    snprintf(esc, sizeof(esc), "\"%u.%u.%u.%u:%u\"",
                             ip0, ip1, ip2, ip3, port);
                } else {
                    snprintf(esc, sizeof(esc), "\"family(%u)\"", family);
                }
                printf("%s}\n", esc);
            } else {
                json_write_str(esc, value.data, MAX_DATA);
                printf("%s}\n", esc);
            }

            count++;
            fflush(stdout);
        }
        if (bpf_map_get_next_key(map_fd, &key, &next_key) < 0)
            break;
    }

    close(map_fd);
    return 0;
}
