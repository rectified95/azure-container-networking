#include <stdlib.h>
#include "bpf/bpf.h"
#include "bpf/libbpf.h"

#define DEFAULT_MAP_PIN_PATH_PREFIX "/ebpf/global/"
#define INVALID_MAP_FD -1

#define COMP_PMAP_NAME_PREFIX "compartment_policy_map_"
#define GLOBAL_PMAP_NAME "map_policy_maps"
#define IP_CACHE_MAP_NAME "ip_cache_map"

#define POLICY_MAP_SIZE 200
#define MAX_POD_SIZE 15
#define IP_CACHE_MAP_SIZE 1000
#define POLICY_MAP_ID 10

typedef enum direction
{
    INGRESS,
    EGRESS,
} direction_t;

#define CGROUP_ACT_OK 0
#define CGROUP_ACT_REJECT 1

typedef struct policy_map_key
{
    uint32_t remote_pod_label_id;
    // uint8_t protocol;  by default, we are using TCP protocol
    uint8_t direction;
    uint16_t remote_port;
} policy_map_key_t;

typedef struct ip_address
{
    union
    {
        uint32_t ipv4; ///< In network byte order.
        uint8_t ipv6[16];
    };
} ip_address_t;

struct npm_endpoint_prog_t test_ebpf_prog();
int attach_progs(struct npm_endpoint_prog_t npm_ep);
int attach_progs_to_compartment(struct npm_endpoint_prog_t npm_ep, int compartment_id);
int update_comp_policy_map(int remote_pod_label_id, direction_t direction, uint16_t remote_port, int compartment_id, int policy_id, bool delete);
int update_ip_cache4(uint32_t ctx_label_id, uint32_t ipv4, bool delete);
int update_global_policy_map(int compartment_id);
//int update_global_policy_map_correct(int compartment_id);

typedef struct bpf_object go_bpf_obj;
typedef int32_t fd_t;

typedef enum map_types
{
    COMP_POLICY_MAP,
    GLOBAL_POLICY_MAP,
    IP_CACHE_MAP,
} map_type_t;

struct _map_properties
{
    int map_type;
    int key_size;
    int value_size;
    int max_entries;
};

struct npm_endpoint_prog_t
{
    struct bpf_object *object;
    struct bpf_program *connect4_program;
    struct bpf_program *connect6_program;
    struct bpf_program *recv4_accept_program;
    struct bpf_program *recv6_accept_program;
};
