#include "bpf_helpers.h"
#include "ebpf_structs.h"

#define POLICY_MAP_SIZE 200
#define MAX_POD_SIZE 15
#define IP_CACHE_MAP_SIZE 1000

#define INGRESS 0
#define EGRESS 1

typedef struct policy_map_key
{
    uint32_t remote_pod_label;
    uint8_t protocol;
    uint8_t direction;
    uint16_t remote_port;
} policy_map_key_t;

