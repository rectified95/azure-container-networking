// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

#include "bpf_helpers.h"
#include "endpoint_prog.h"
#include "bpf_endian.h"
#define PIN_GLOBAL_NS 2
// define the policy map
SEC("maps")
struct bpf_map_def compartment_policy_map = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(policy_map_key_t), // key is remote label id + direction + port/proto
    .value_size = sizeof(uint32_t),       // value is policy ID
    .max_entries = POLICY_MAP_SIZE,
    .id = POLICY_MAP_ID,
    .pinning = PIN_GLOBAL_NS};

// define the outer map of policy map policy map
SEC("maps")
struct bpf_map_def map_policy_maps = {
    .type = BPF_MAP_TYPE_ARRAY_OF_MAPS,
    .key_size = sizeof(uint32_t),   // key is a compartment ID
    .value_size = sizeof(uint32_t), // value is ID of the policy map specific to that compartment
    .max_entries = MAX_POD_SIZE,    // max number of pods in test cluster
    .inner_id = POLICY_MAP_ID,      // id of policy_map in the ELF file
    .pinning = PIN_GLOBAL_NS};     

// declare ipCache map
SEC("maps")
struct bpf_map_def ip_cache_map = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(ip_address_t),
    .value_size = sizeof(uint32_t),
    .max_entries = IP_CACHE_MAP_SIZE,
    .pinning = PIN_GLOBAL_NS};

SEC("maps")
struct bpf_map_def prog_array_map = {
    .type = BPF_MAP_TYPE_PROG_ARRAY,
    .key_size = sizeof(uint32_t), 
    .value_size = sizeof(uint32_t), 
    .max_entries = 2};

SEC("maps")
struct bpf_map_def tail_call_state_cache = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(bpf_sock_addr_t),    // key - ctx
    .value_size = sizeof(tail_cache_val_t), // val - struct {remote_pod_label; direction}
    .max_entries = 100};

// TODO declare identity cache map

__always_inline int
_policy_eval(bpf_sock_addr_t *ctx)
{
    bpf_sock_addr_t ctx_cpy = *ctx;
    tail_cache_val_t* cache_val = (tail_cache_val_t*) bpf_map_lookup_elem(&tail_call_state_cache, &ctx_cpy);
    if (!cache_val) {
        return BPF_SOCK_ADDR_VERDICT_REJECT;
    }

    policy_map_key_t key = cache_val->lookup_key;
    uint32_t comp_id = ctx->compartment_id;
   
    bpf_map_delete_elem(&tail_call_state_cache, &ctx_cpy);

    void *policy_map_id = (uint32_t *)bpf_map_lookup_elem(&map_policy_maps, &comp_id);
    if (policy_map_id == NULL)
    {
        // If there is no policy map attached to this compartment, 
        // then no policy is applied, allow all traffic.
        bpf_printk("Policy Eval: No policy map for compartment id %d - allowing traffic.", 
            ctx->compartment_id);
        return BPF_SOCK_ADDR_VERDICT_PROCEED;
    };
    
    // bpf_printk("Comp_policy map found; remoteLabel %d, port %d, dir %d\n", 
    //     key.remote_pod_label_id, key.remote_port, key.direction);  

    // Look up L4 first 
    uint32_t *verdict = bpf_map_lookup_elem(policy_map_id, &key);
    if (verdict != NULL)
    {
        bpf_printk("Policy Eval: L4 policy ID %lu Allowed, remote_pod_label %d.", 
            *verdict, key.remote_pod_label_id);
        return BPF_SOCK_ADDR_VERDICT_PROCEED;
    }
    bpf_printk("No L4 rules found; Looked up policy map with labelid: %d, direction: %d, remote port: %d\n", 
             key.remote_pod_label_id, key.direction, key.remote_port);

    // // Look up L3 rules
    key.remote_port = 0;
    verdict = bpf_map_lookup_elem(policy_map_id, &key);
    if (verdict != NULL)
    {
        bpf_printk("Policy Eval: L3 policy ID %lu Allowed.", *verdict);
        return BPF_SOCK_ADDR_VERDICT_PROCEED;
    }

    bpf_printk("Dropping packet: no L3 rules found for labelid: %d, direction: %d, remote port: %d\n", 
             key.remote_pod_label_id, key.direction, key.remote_port);

    return BPF_SOCK_ADDR_VERDICT_REJECT;
}

__always_inline int
authorize_v4(bpf_sock_addr_t *ctx, direction_t dir)
{
    ip_address_t ip_to_lookup = {0};
    ip_to_lookup.ipv4 = ctx->user_ip4;
    if (dir == INGRESS)
    {
        ip_to_lookup.ipv4 = ctx->msg_src_ip4;
    }

    uint32_t *ctx_label_id = NULL;
    ctx_label_id = (uint32_t *)bpf_map_lookup_elem(&ip_cache_map, &ip_to_lookup);
    if (ctx_label_id == NULL)
    {
        bpf_printk("No label found for IP %u port %u, dropping packet.",
            bpf_ntohl(ip_to_lookup.ipv4), bpf_ntohs(ctx->user_port));

        // (TODO) comment different from code

        // if there is no Identity assigned then CP is yet to sync
        // allow all traffic.
        return BPF_SOCK_ADDR_VERDICT_REJECT;
    }

    bpf_printk("Looked up label %d for remote ip %d\n", 
        *ctx_label_id, ip_to_lookup.ipv4);

    if (*ctx_label_id == 200) {
        bpf_printk("Label 200(ANY) - allow.");
        return BPF_SOCK_ADDR_VERDICT_PROCEED;
    }
    
    policy_map_key_t key = {0};
    key.remote_pod_label_id = *ctx_label_id;
    key.remote_port = ctx->user_port;
    key.protocol = 0;
    key.direction = dir;

    tail_cache_val_t cache = {0};
    cache.lookup_key = key;
    bpf_sock_addr_t ctx_cpy = *ctx;

    bpf_map_update_elem(&tail_call_state_cache, &ctx_cpy, &cache, 0);

    return 0; // Return val ignored due to upcoming tail call.
}

SEC("cgroup/connect4_0")
int authorize_connect4_0(bpf_sock_addr_t *ctx)
{
    bpf_printk("1. tail call link - inside connect4_0");
    bpf_printk("Connect4 called srcip: %u, dstip: %u, dstport: %u", 
        bpf_ntohl(ctx->msg_src_ip4), bpf_ntohl(ctx->user_ip4), bpf_ntohs(ctx->user_port));
    
    int _ = authorize_v4(ctx, EGRESS);

    bpf_tail_call(ctx, &prog_array_map, 1);

    return BPF_SOCK_ADDR_VERDICT_REJECT;
}

SEC("cgroup/policy_eval")
int policy_eval_prog(bpf_sock_addr_t *ctx)
{
    bpf_printk("2. tail call link");
    return _policy_eval(ctx);
}

SEC("cgroup/recv_accept4")
int authorize_recv_accept4(bpf_sock_addr_t *ctx)
{
    bpf_printk("inside recv_accept4_0\n");
    bpf_printk("Recv_accept4 called srcip: %u, dstip: %u, dstport: %u", 
        bpf_ntohl(ctx->msg_src_ip4),  bpf_ntohl(ctx->user_ip4), bpf_ntohs(ctx->user_port));

    int _ = authorize_v4(ctx, INGRESS);
    bpf_tail_call(ctx, &prog_array_map, 1);

    return BPF_SOCK_ADDR_VERDICT_REJECT; 
}


// ### IPv6 ### //
// ###      ### //
__always_inline int
authorize_v6(bpf_sock_addr_t *ctx, direction_t dir)
{
    ip_address_t ip_to_lookup = {0};
    __builtin_memcpy(ip_to_lookup.ipv6, ctx->msg_src_ip6, sizeof(ctx->msg_src_ip6));
    if (dir == INGRESS)
    {
        __builtin_memcpy(ip_to_lookup.ipv6, ctx->user_ip6, sizeof(ctx->msg_src_ip6));
    }

    /* with this below check for some reason verification fails.

    int32_t *policy_map_fd =  (int32_t *)bpf_map_lookup_elem(&map_policy_maps, &ctx->compartment_id);
    if (policy_map_fd == NULL)
    {
        bpf_printk("Policy Eval: No policy map for compartment");
        // if there is no policy map attached to this compartment
        // then no policy is applied, allow all traffic.
        return BPF_SOCK_ADDR_VERDICT_PROCEED;
    }
    */

    uint32_t *ctx_label_id = NULL;
    ctx_label_id = (uint32_t *)bpf_map_lookup_elem(&ip_cache_map, &ip_to_lookup);
    if (ctx_label_id == NULL)
    {
        bpf_printk("No label found for IP %u, dstport %u, dropping packet.", bpf_ntohl(ctx->user_ip4), bpf_ntohs(ctx->user_port));
        // if there is no Identity assigned then CP is yet to sync
        // allow all traffic.
        return BPF_SOCK_ADDR_VERDICT_REJECT;
    }

    policy_map_key_t key = {0};
    key.remote_pod_label_id = *ctx_label_id;
    key.remote_port = ctx->user_port;
    // key.protocol = ctx->protocol;
    key.direction = dir;

    return _policy_eval(ctx);
}

// TODO - implement
SEC("cgroup/connect6")
int authorize_connect6(bpf_sock_addr_t *ctx)
{
    bpf_printk("Connect6 called");

    return authorize_v6(ctx, EGRESS);
}

// TODO - implement
SEC("cgroup/recv_accept6")
int authorize_recv_accept6(bpf_sock_addr_t *ctx)
{
    bpf_printk("Recv_accept6 called");

    return authorize_v6(ctx, INGRESS);
}
