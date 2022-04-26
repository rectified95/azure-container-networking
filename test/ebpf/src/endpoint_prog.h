#include "bpf_helpers.h"
#include "ebpf_structs.h"

#define POLICY_MAP_SIZE 200
#define MAX_POD_SIZE 15
#define IP_CACHE_MAP_SIZE 1000
#define POLICY_MAP_ID 10

#define INGRESS 0
#define EGRESS 1

#define CGROUP_ACT_OK 0
#define CGROUP_ACT_REJECT 1

typedef struct policy_map_key
{
    uint32_t remote_pod_label;
    uint8_t protocol;
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