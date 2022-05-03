#include <stdlib.h>
#include "bpf/bpf.h"
#include "bpf/libbpf.h"

#define DEFAULT_MAP_PIN_PATH_PREFIX "/ebpf/global/"
#define INVALID_MAP_FD -1

#define COMP_PMAP_NAME_PREFIX "compartment_policy_map_"
#define GLOBAL_PMAP_NAME "map_policy_maps"
#define IP_CACHE_MAP_NAME "ip_cache_map"

struct npm_endpoint_prog_t test_ebpf_prog();
int attach_progs(struct npm_endpoint_prog_t npm_ep);

typedef struct bpf_object go_bpf_obj;

typedef enum map_types
{
    COMP_POLICY_MAP,
    GLOBAL_POLICY_MAP,
    IP_CACHE_MAP,
} map_type_t;

typedef struct _map_properties
{
    map_type_t internal_map_type;
    int map_type;
    int key_size;
    int value_size;
    int max_entries;
} map_properties_t;

const struct map_properties_t *comp_policy_map_properties = {
    .map_type = BPF_MAP_TYPE_HASH,
    .internal_map_type = COMP_POLICY_MAP,
    .key_size = sizeof(policy_map_key_t),
    .value_size = sizeof(uint32_t),
    .max_entries = POLICY_MAP_SIZE,
};

const struct map_properties_t *global_policy_map_properties = {
    .map_type = BPF_MAP_TYPE_ARRAY_OF_MAPS,
    .internal_map_type = GLOBAL_POLICY_MAP,
    .key_size = sizeof(uint32_t),
    .value_size = sizeof(uint32_t),
    .max_entries = MAX_POD_SIZE,
};

const struct map_properties_t *ip_cache_map_properties = {
    .map_type = BPF_MAP_TYPE_LPM_TRIE,
    .internal_map_type = IP_CACHE_MAP,
    .key_size = sizeof(ip_address_t),
    .value_size = sizeof(uint32_t),
    .max_entries = IP_CACHE_MAP_SIZE,
};

struct npm_endpoint_prog_t
{
    struct bpf_object *object;
    struct bpf_program *connect4_program;
    struct bpf_program *connect6_program;
    struct bpf_program *recv4_accept_program;
    struct bpf_program *recv6_accept_program;
};
