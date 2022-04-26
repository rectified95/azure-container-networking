// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

#include "bpf_helpers.h"
#include "ebpf_structs.h"
#include "ebpf_nethooks.h"
#include "endpoint_prog.h"

// define the policy map
SEC("maps")
ebpf_map_definition_in_file_t compartment_policy_map = {
    .size = sizeof(ebpf_map_definition_in_file_t),
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(policy_map_key_t), // key is remote label id + direction + port/proto
    .value_size = sizeof(uint32_t),       // value is policy ID
    .max_entries = POLICY_MAP_SIZE};

// define the outer map of policy map policy map
SEC("maps")
ebpf_map_definition_in_file_t map_policy_maps = {
    .size = sizeof(ebpf_map_definition_in_file_t),
    .type = BPF_MAP_TYPE_ARRAY_OF_MAPS,
    .key_size = sizeof(uint32_t),   // key is a compartment ID
    .value_size = sizeof(uint32_t), // value is FD of the policy map specific to that compartment
    .max_entries = MAX_POD_SIZE};   // max number of pods in test cluster
// .inner_map_id = POLICY_MAP_ID}; ///< id of policy_map in the ELF file

// declare ipCache map
SEC("maps")
ebpf_map_definition_in_file_t ip_cache_map =    {
        .size = sizeof(ebpf_map_definition_in_file_t),
        .type = BPF_MAP_TYPE_LPM_TRIE,
        .key_size = sizeof(ip_address_t),
        .value_size = sizeof(uint32_t),
        .max_entries = IP_CACHE_MAP_SIZE};

// TODO declare identity cache map

__inline int
_policy_eval(bpf_sock_addr_t *ctx, uint32_t compartment_id, policy_map_key_t key)
{

    int *verdict = NULL;
    int32_t policy_map_fd = bpf_map_lookup_elem(&map_policy_maps, &compartment_id);

    // Look up L4 first
    verdict = bpf_map_lookup_elem(&policy_map_fd, &key);

    if (verdict == NULL)
    {
        // Look up L3 rules
        key.remote_port = 0;
        verdict = bpf_map_lookup_elem(&policy_map_fd, &key);
    }

    return (verdict != NULL) ? *verdict : 1;
}

__inline int
authorize_v4(bpf_sock_addr_t *ctx, uint8_t direction)
{

    ip_address_t ip_to_lookup = {0};
    ip_to_lookup.ipv4 = ctx->msg_src_ip4;
    if (direction == INGRESS)
    {
        ip_to_lookup.ipv4 = ctx->user_ip4;
    }

    uint32_t ctx_label_id = bpf_map_lookup_elem(&ip_cache_map, &ip_to_lookup);
    policy_map_key_t key = {0};
    key.remote_pod_label = ctx_label_id;
    key.remote_port = ctx->user_port;
    key.protocol = ctx->protocol;
    key.direction = direction;

    return _policy_eval(ctx, ctx->compartment_id, key);
}

__inline int
authorize_v6(bpf_sock_addr_t *ctx, uint8_t direction)
{
    ip_address_t ip_to_lookup = {0};
    __builtin_memcpy(ip_to_lookup.ipv6, ctx->msg_src_ip6, sizeof(ctx->msg_src_ip6));
    if (direction == INGRESS)
    {
        __builtin_memcpy(ip_to_lookup.ipv6, ctx->user_ip6, sizeof(ctx->msg_src_ip6));
    }

    uint32_t ctx_label_id = bpf_map_lookup_elem(&ip_cache_map, &ip_to_lookup);

    policy_map_key_t key = {0};
    key.remote_pod_label = ctx_label_id;
    key.remote_port = ctx->user_port;
    key.protocol = ctx->protocol;
    key.direction = direction;

    return _policy_eval(ctx, ctx->compartment_id, key);
}

SEC("cgroup/connect4")
int authorize_connect4(bpf_sock_addr_t *ctx)
{
    return authorize_v4(ctx, EGRESS);
}

SEC("cgroup/connect6")
int authorize_connect6(bpf_sock_addr_t *ctx)
{
    return authorize_v6(ctx, EGRESS);
}

SEC("cgroup/recv_accept4")
int authorize_recv_accept4(bpf_sock_addr_t *ctx)
{
    return authorize_v4(ctx, INGRESS);
}

SEC("cgroup/recv_accept6")
int authorize_recv_accept6(bpf_sock_addr_t *ctx)
{
    return authorize_v6(ctx, INGRESS);
}