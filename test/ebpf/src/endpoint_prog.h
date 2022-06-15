#include "bpf_helpers.h"

#define POLICY_MAP_SIZE 200
#define MAX_POD_SIZE 15
#define IP_CACHE_MAP_SIZE 1000
#define POLICY_MAP_ID 999

typedef enum direction
{
    INGRESS,
    EGRESS,
} direction_t;

typedef struct policy_map_key
{
    uint32_t remote_pod_label_id;
    uint8_t direction;
    uint16_t remote_port;
    uint8_t protocol; // by default, we are using TCP protocol
} policy_map_key_t;

typedef struct tail_cache_val
{
    policy_map_key_t lookup_key;
} tail_cache_val_t;

typedef struct ip_address
{
    union
    {
        uint32_t ipv4; ///< In network byte order.
        uint8_t ipv6[16];
    };
} ip_address_t;