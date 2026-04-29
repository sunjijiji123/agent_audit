/* loader.h — public API for loader.so */

#ifndef LOADER_H
#define LOADER_H

int bpf_map_update_target_comm(const char *comm);
int bpf_map_delete_target_comm(const char *comm);
int bpf_map_clear_target_comms(void);

#endif /* LOADER_H */
