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
    .id = POLICY_MAP_ID};

// define the outer map of policy map policy map
SEC("maps")
struct bpf_map_def map_policy_maps = {
    .type = BPF_MAP_TYPE_ARRAY_OF_MAPS,
    .key_size = sizeof(uint32_t),   // key is a compartment ID
    .value_size = sizeof(uint32_t), // value is ID of the policy map specific to that compartment
    .max_entries = MAX_POD_SIZE,    // max number of pods in test cluster
    .inner_id = POLICY_MAP_ID,  // id of policy_map in the ELF file
    .pinning = PIN_GLOBAL_NS};     

// declare ipCache map
SEC("maps")
struct bpf_map_def ip_cache_map = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(ip_address_t),
    .value_size = sizeof(uint32_t),
    .max_entries = IP_CACHE_MAP_SIZE,
    .pinning = PIN_GLOBAL_NS};

// TODO declare identity cache map

__inline int
_policy_eval(bpf_sock_addr_t *ctx, uint32_t compartment_id, policy_map_key_t key)
{
    uint32_t *verdict = NULL;
    void *policy_map_fd = (uint32_t *)bpf_map_lookup_elem(&map_policy_maps, &compartment_id);
    if (policy_map_fd == NULL)
    {
        //bpf_printk("Policy Eval: No policy map for compartment");
        // if there is no policy map attached to this compartment
        // then no policy is applied, allow all traffic.
        bpf_printk("com_policy_map NOT found for compartmentid: %d - allowing traffic\n", compartment_id);
        return BPF_SOCK_ADDR_VERDICT_PROCEED;
    }
    //else {
    //    bpf_printk("com_policy map found for compartmentid: %d, direction: %d, remote port: %d\n", compartment_id);
    //}   

    // Look up L4 first
    bpf_printk("found com_policy_fd %d for com_id %d\n", *(uint32_t *) policy_map_fd, compartment_id);
    //verdict = bpf_map_lookup_elem(policy_map_fd, &key);
    // if (verdict != NULL)
    // {
    //     // char msg[128];
    //     //bpf_printk("Policy Eval: L4 policy ID %lu Allowed.", *verdict);
    //     // bpf_printk(msg);
    //     //bpf_printk("found rule for remote label\n", key.remote_pod_label_id);
    //     return BPF_SOCK_ADDR_VERDICT_PROCEED;
    // }//else {
       // bpf_printk("no L4 rules found for labelid: %d, direction: %d, remote port: %d\n", key.remote_pod_label_id, key.direction, key.remote_port);
    //}   

    // Look up L3 rules
    // key.remote_port = 0;
    // verdict = bpf_map_lookup_elem(policy_map_fd, &key);
    // if (verdict != NULL)
    // {
    //     // char msg[128];
    //    // bpf_printk("Policy Eval: L3 policy ID %lu Allowed.", *verdict);
    //     // bpf_printk(msg);
    //     return BPF_SOCK_ADDR_VERDICT_PROCEED;
    // } else {
    //    // bpf_printk("no L3 rules found for labelid: %d, direction: %d, remote port: %d\n", key.remote_pod_label_id, key.direction, key.remote_port);
    // }   

    return BPF_SOCK_ADDR_VERDICT_REJECT;
}

__inline int
authorize_v4(bpf_sock_addr_t *ctx, direction_t dir)
{
    ip_address_t ip_to_lookup = {0};
    ip_to_lookup.ipv4 = ctx->user_ip4;
    if (dir == INGRESS)
    {
        ip_to_lookup.ipv4 = ctx->msg_src_ip4;
    }

    /*
        uint32_t comp_id =  ctx->compartment_id;
        int32_t *policy_map_fd =  (int32_t *)bpf_map_lookup_elem(&map_policy_maps, &comp_id);
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
    { // (TODO) default ctx_label_id to 200 (ANY)
        //bpf_printk("No label found for IP %u port %u, dropping packet.", bpf_ntohl(ip_to_lookup.ipv4), bpf_ntohs(ctx->user_port));
        // if there is no Identity assigned then CP is yet to sync
        // allow all traffic.
        return BPF_SOCK_ADDR_VERDICT_REJECT;
    }
    
    bpf_printk("looked up label %d for remote ip %d on comp_id %d\n", 
        *ctx_label_id, ip_to_lookup.ipv4, ctx->compartment_id);
    
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

    return _policy_eval(ctx, ctx->compartment_id, key);
}



SEC("cgroup/connect4")
int authorize_connect4(bpf_sock_addr_t *ctx)
{
    uint32_t hostip = bpf_ntohl(ctx->user_ip4);
    bpf_printk("Connect4 called srcip: %u, dstip: %u, dstport: %u", bpf_ntohl(ctx->msg_src_ip4), bpf_ntohl(ctx->user_ip4), bpf_ntohs(ctx->user_port));
    return authorize_v4(ctx, EGRESS);
}

SEC("cgroup/connect6")
int authorize_connect6(bpf_sock_addr_t *ctx)
{
    bpf_printk("Connect6 called");

    return authorize_v6(ctx, EGRESS);
}

SEC("cgroup/recv_accept4")
int authorize_recv_accept4(bpf_sock_addr_t *ctx)
{
    bpf_printk("Recv_accept4 called srcip: %u, dstip: %u, dstport: %u", bpf_ntohl(ctx->msg_src_ip4),  bpf_ntohl(ctx->user_ip4), bpf_ntohs(ctx->user_port));

    return authorize_v4(ctx, INGRESS);
}

SEC("cgroup/recv_accept6")
int authorize_recv_accept6(bpf_sock_addr_t *ctx)
{
    bpf_printk("Recv_accept6 called");

    return authorize_v6(ctx, INGRESS);
}