// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

#include "bpf_helpers.h"
#include "endpoint_prog.h"

/*
this below map definition is from test/ebpf/src/cgroup_sock_addr.c
and is failing at size

.\endpoint_prog.c:21:6: error: field designator 'size' does not refer to any field in type 'ebpf_map_definition_in_file_t' (aka 'struct _ebpf_map_definition_in_file')
    .size = sizeof(ebpf_map_definition_in_file_t),

ebpf_map_definition_in_file_t ip_cache_map = {
    .size = sizeof(ebpf_map_definition_in_file_t),
    .type = BPF_MAP_TYPE_LPM_TRIE,
    .key_size = sizeof(ip_address_t),
    .value_size = sizeof(uint32_t),
    .max_entries = IP_CACHE_MAP_SIZE};
*/

// define the policy map
SEC("maps")
struct bpf_map_def compartment_policy_map = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(policy_map_key_t), // key is remote label id + direction + port/proto
    .value_size = sizeof(uint32_t),       // value is policy ID
    .max_entries = POLICY_MAP_SIZE,
    .id = POLICY_MAP_ID};

// define the outer map of policy map policy map
SEC("maps")
struct bpf_map_def map_policy_maps = {
    .type = BPF_MAP_TYPE_ARRAY_OF_MAPS,
    .key_size = sizeof(uint32_t),   // key is a compartment ID
    .value_size = sizeof(uint32_t), // value is FD of the policy map specific to that compartment
    .max_entries = MAX_POD_SIZE,    // max number of pods in test cluster
    .inner_id = POLICY_MAP_ID};     ///< id of policy_map in the ELF file

// declare ipCache map
SEC("maps")
struct bpf_map_def ip_cache_map = {
    .type = BPF_MAP_TYPE_LPM_TRIE,
    .key_size = sizeof(ip_address_t),
    .value_size = sizeof(uint32_t),
    .max_entries = IP_CACHE_MAP_SIZE};

// TODO declare identity cache map

__inline int
_policy_eval(bpf_sock_addr_t *ctx, uint32_t compartment_id, policy_map_key_t key)
{
    int *verdict = NULL;
    void *policy_map_fd = (int32_t *)bpf_map_lookup_elem(&map_policy_maps, &compartment_id);
    if (policy_map_fd == NULL)
    {
        print_trace(ctx, "Policy Eval: No policy map for compartment");
        // if there is no policy map attached to this compartment
        // then no policy is applied, allow all traffic.
        return CGROUP_ACT_OK;
    }

    // Look up L4 first
    verdict = bpf_map_lookup_elem(policy_map_fd, &key);
    if (verdict != NULL)
    {
        char msg[128];
        bpf_snprintf(msg, sizeof(msg), "Policy Eval: L4 policy ID %d Allowed.", *verdict, sizeof(*verdict));
        print_trace(ctx, msg);
        return CGROUP_ACT_OK;
    }

    // Look up L3 rules
    key.remote_port = 0;
    verdict = bpf_map_lookup_elem(policy_map_fd, &key);
    if (verdict != NULL)
    {
        char msg[128];
        bpf_snprintf(msg, sizeof(msg), "Policy Eval: L3 policy ID %d Allowed.", *verdict, sizeof(*verdict));
        print_trace(ctx, msg);
        return CGROUP_ACT_OK;
    }

    return CGROUP_ACT_REJECT;
}

__inline int
authorize_v4(bpf_sock_addr_t *ctx, direction_t dir)
{
    ip_address_t ip_to_lookup = {0};
    ip_to_lookup.ipv4 = ctx->msg_src_ip4;
    if (dir == INGRESS)
    {
        ip_to_lookup.ipv4 = ctx->user_ip4;
    }

    uint32_t *ctx_label_id = NULL;
    ctx_label_id = (uint32_t *)bpf_map_lookup_elem(&ip_cache_map, &ip_to_lookup);
    if (ctx_label_id == NULL)
    {
        print_trace(ctx, "No label found for IP");
        // if there is no Identity assigned then CP is yet to sync
        // allow all traffic.
        return CGROUP_ACT_OK;
    }

    policy_map_key_t key = {0};
    key.remote_pod_label_id = *ctx_label_id;
    key.remote_port = ctx->user_port;
    // key.protocol = ctx->protocol;
    key.direction = dir;

    return _policy_eval(ctx, ctx->compartment_id, key);
}

__inline int
authorize_v6(bpf_sock_addr_t *ctx, direction_t dir)
{
    ip_address_t ip_to_lookup = {0};
    __builtin_memcpy(ip_to_lookup.ipv6, ctx->msg_src_ip6, sizeof(ctx->msg_src_ip6));
    if (dir == INGRESS)
    {
        __builtin_memcpy(ip_to_lookup.ipv6, ctx->user_ip6, sizeof(ctx->msg_src_ip6));
    }

    uint32_t *ctx_label_id = NULL;
    ctx_label_id = (uint32_t *)bpf_map_lookup_elem(&ip_cache_map, &ip_to_lookup);
    if (ctx_label_id == NULL)
    {
        print_trace(ctx, "No label found for IP");
        // if there is no Identity assigned then CP is yet to sync
        // allow all traffic.
        return CGROUP_ACT_OK;
    }

    policy_map_key_t key = {0};
    key.remote_pod_label_id = *ctx_label_id;
    key.remote_port = ctx->user_port;
    // key.protocol = ctx->protocol;
    key.direction = dir;

    return _policy_eval(ctx, ctx->compartment_id, key);
}

__inline void
print_trace(bpf_sock_addr_t *ctx, char *msg)
{
    bpf_printk("%s. Packet info: Src IP: %x, Dst IP: %x, Src Port: %d, Dst Port: %d, Compartment ID: %d\n", msg, ctx->msg_src_ip4, ctx->msg_dst_ip4, ctx->user_port, ctx->msg_dst_port, ctx->compartment_id);
}

SEC("cgroup/connect4")
int authorize_connect4(bpf_sock_addr_t *ctx)
{
    print_trace(ctx, "Connect4 called.");
    return authorize_v4(ctx, EGRESS);
}

SEC("cgroup/connect6")
int authorize_connect6(bpf_sock_addr_t *ctx)
{
    print_trace(ctx, "Connect6 called.");
    return authorize_v6(ctx, EGRESS);
}

SEC("cgroup/recv_accept4")
int authorize_recv_accept4(bpf_sock_addr_t *ctx)
{
    print_trace(ctx, "Recv_accept4 called.");
    return authorize_v4(ctx, INGRESS);
}

SEC("cgroup/recv_accept6")
int authorize_recv_accept6(bpf_sock_addr_t *ctx)
{
    print_trace(ctx, "Recv_accept6 called.");
    return authorize_v6(ctx, INGRESS);
}