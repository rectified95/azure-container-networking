
#include <stdlib.h>
#include <string.h>
#include "bpf/bpf.h"
#include "ebpf_result.h"
//#include "ebpf_api.h"
#include "sal.h"
#include "bpf/libbpf.h"
#include "testSockProg.h"
#include "bpf_endian.h"

ebpf_result_t
ebpf_object_unpin(const char* path);
char *get_map_pin_path(const char *map_name)
{
    char *map_pin_path = malloc(sizeof(char) * (strlen(map_name) + strlen(DEFAULT_MAP_PIN_PATH_PREFIX) + 1));
    if (map_pin_path == NULL)
    {
        return NULL;
    }
    strcpy(map_pin_path, DEFAULT_MAP_PIN_PATH_PREFIX);
    strcat(map_pin_path, map_name);
    return map_pin_path;
}

void get_epmap_name(int internal_map_type, int comp_id, char **full_map_name)
{
    printf("in get_epmap_name func\n");
    switch (internal_map_type)
    {
    case COMP_POLICY_MAP:
    {
        int prefixlen = strlen(COMP_PMAP_NAME_PREFIX) + 5;
        char *numVal;
        numVal = (char *)malloc(prefixlen * sizeof(char));
        if (numVal == NULL)
        {
            printf("malloc failed\n");
            return;
        }
        sprintf(numVal, "%s%d", COMP_PMAP_NAME_PREFIX, comp_id);
        *full_map_name = numVal;
        break;
    }
    case GLOBAL_POLICY_MAP:
        *full_map_name = GLOBAL_PMAP_NAME;
        break;
    case IP_CACHE_MAP:
        *full_map_name = IP_CACHE_MAP_NAME;
        break;
    }
}

int pin_given_map(int internal_map_type, fd_t fd)
{
    char *map_name = NULL;
    get_epmap_name(internal_map_type, POLICY_MAP_ID, &map_name);
    if (map_name == NULL)
    {
        return -1;
    }

    printf("pin_given_map: map name: %s\n", map_name);
    // Map fd is invalid. Open fd to the map.
    char *pin_path = get_map_pin_path(map_name);
    if (pin_path == NULL)
    {
        return -1;
    }
    printf("pin_given_map: map pinned path %s\n", pin_path);
    fd_t fdnew = bpf_obj_get(pin_path);
    //int res_unpin = bpf_obj_unpin(fd, pin_path);
    //ebpf_result_t resunpin = ebpf_object_unpin(pin_path);
    //printf("path %s unpin res %d\n", pin_path, res_unpin);
    
    if (fdnew != INVALID_MAP_FD)
    {
        printf("pin_given_map: found the pinned map FD\n");
        return 0;
    }

    printf("pin_given_map: pinned map not found, creating pin for map %s\n", map_name);
    // Map created. Now pin the map.
    int error = bpf_obj_pin(fd, pin_path);
    //res_unpin = bpf_obj_unpin(fd, pin_path);
    //printf("path %s unpin res %d\n", pin_path, res_unpin);
    return 0;
    if (error != 0)
    {
        return -1;
    }
    return 0;
}

struct npm_endpoint_prog_t test_ebpf_prog()
{
    const char *connect4_0_program_name = "authorize_connect4_0";
    const char *policy_eval_program__name = "policy_eval_prog";

    const char *connect6_program_name = "authorize_connect6";
    const char *recv4_accept_program_name = "authorize_recv_accept4";
    const char *recv6_accept_program_name = "authorize_recv_accept6";
    struct npm_endpoint_prog_t _npm_endpoint_prog_t;
    struct bpf_object *object;
    int program_fd;
    int result = bpf_prog_load("src/endpoint_prog.o", BPF_PROG_TYPE_CGROUP_SOCK_ADDR, &object, &program_fd);
    

    if (!object)
    {
        printf("object is null\n");
        return _npm_endpoint_prog_t;
    }
    printf("Loaded eBPF program.\n");

    if (result < 0)
    {
        printf("Load program failed\n");
        return _npm_endpoint_prog_t;
    }

    _npm_endpoint_prog_t.object = object;

    printf("Getting the bpf_prog for connect program 4_0\n");
    struct bpf_program *connect_0_program = bpf_object__find_program_by_name(object, connect4_0_program_name);
    if (!connect_0_program)
    {
        printf("%s is null\n", connect4_0_program_name);
        return _npm_endpoint_prog_t;
    }

    printf("Getting the bpf_prog for policy_eval program\n");
    struct bpf_program *policy_eval_program = bpf_object__find_program_by_name(object, policy_eval_program__name);
    if (!policy_eval_program)
    {
        printf("%s is null\n", policy_eval_program__name);
        return _npm_endpoint_prog_t;
    }

    _npm_endpoint_prog_t.connect4_0_program = connect_0_program;
    _npm_endpoint_prog_t.policy_eval_program = policy_eval_program;
    fd_t callee1_fd = bpf_program__fd(policy_eval_program);
    fd_t prog_map_fd = bpf_object__find_map_fd_by_name(object, "prog_array_map");
    uint32_t index = 1;
    bpf_map_update_elem(prog_map_fd, &index, &callee1_fd, 0);
    printf("callee_1 close res %d", _close(callee1_fd));

    struct bpf_program *connect6_program = bpf_object__find_program_by_name(object, connect6_program_name);
    if (!connect6_program) 
    {
        printf("%s is null\n", connect6_program_name);
        return _npm_endpoint_prog_t;
    }

    _npm_endpoint_prog_t.connect6_program = connect6_program;

    struct bpf_program *recv_accept_program = bpf_object__find_program_by_name(object, recv4_accept_program_name);
    if (!recv_accept_program)
    {
        printf("%s is null\n", recv4_accept_program_name);
        return _npm_endpoint_prog_t;
    }

    _npm_endpoint_prog_t.recv4_accept_program = recv_accept_program;

    struct bpf_program *recv6_accept_program = bpf_object__find_program_by_name(object, recv6_accept_program_name);
    if (!recv6_accept_program)
    {
        printf("%s is null\n", recv6_accept_program_name);
        return _npm_endpoint_prog_t;
    }

    _npm_endpoint_prog_t.recv6_accept_program = recv6_accept_program;

    struct bpf_map *map_policy_maps_obj = bpf_object__find_map_by_name(object, "map_policy_maps");
    if (map_policy_maps_obj == NULL)
    {
        printf("Global policy map is null\n");
        return _npm_endpoint_prog_t;
    }

    int err = pin_given_map(GLOBAL_POLICY_MAP, bpf_map__fd(map_policy_maps_obj));
    if (err < 0)
    {
        printf("Failed to pin GLOBAL POLICY MAP.\n");
        return _npm_endpoint_prog_t;
    }
    printf("Done pinning global policy map.\n");

    struct bpf_map *ip_cache_map_obj = bpf_object__find_map_by_name(object, "ip_cache_map");
    if (ip_cache_map_obj == NULL)
    {
        printf("IP cache map is null.\n");
        return _npm_endpoint_prog_t;
    }

    err = pin_given_map(IP_CACHE_MAP, bpf_map__fd(ip_cache_map_obj));
    if (err < 0)
    {
        printf("Failed to pin ip cache MAP.\n");
        return _npm_endpoint_prog_t;
    }
    printf("Done pinning ip cache map.\n");

    return _npm_endpoint_prog_t;
}

int attach_progs(struct npm_endpoint_prog_t npm_ep)
{
    printf("attaching progs\n");
    printf("attach V4 connect prog\n");
    // attach V4 connect prog
    int result = bpf_prog_attach(bpf_program__fd(npm_ep.connect4_0_program), 0, BPF_CGROUP_INET4_CONNECT, 0);
    if (result != 0)
    {
        printf("Error is null while attaching v4_0 connect prog\n");
        return result;
    }
    result = bpf_prog_attach(bpf_program__fd(npm_ep.policy_eval_program), 0, BPF_CGROUP_INET4_CONNECT, 0);
    if (result != 0)
    {
        printf("Error is null while attaching v4_1 connect prog\n");
        return result;
    }
    printf("attach V6 connect prog\n");
    // attach V6 connect prog
    bpf_prog_attach(bpf_program__fd(npm_ep.connect6_program), 0, BPF_CGROUP_INET6_CONNECT, 0);
    if (result != 0)
    {
        printf("Error while attaching v6 connect prog\n");
        return result;
    }
    printf("attach V4 recv prog\n");
    // attach V4 recv prog
    bpf_prog_attach(bpf_program__fd(npm_ep.recv4_accept_program), 0, BPF_CGROUP_INET4_RECV_ACCEPT, 0);
    if (result != 0)
    {
        printf("Error is null while attaching v4 recv prog\n");
        return result;
    }
    printf("attach V6 recv prog\n");
    // attach V6 recv prog

    bpf_prog_attach(bpf_program__fd(npm_ep.recv6_accept_program), 0, BPF_CGROUP_INET6_RECV_ACCEPT, 0);
    if (result != 0)
    {
        printf("Error is null while attaching v6 recv prog\n");
        return result;
    }

    printf("Done attaching progs\n");
}

int attach_progs_to_compartment(struct npm_endpoint_prog_t npm_ep, int compartment_id)
{
    printf("Attaching progs to compartment %d\n", compartment_id);

    fd_t connect_0_fd = bpf_program__fd(npm_ep.connect4_0_program);
    fd_t connect_1_fd = bpf_program__fd(npm_ep.policy_eval_program);

    int result = bpf_prog_attach(connect_0_fd, compartment_id, BPF_CGROUP_INET4_CONNECT, 0);
    if (result != 0)
    {
        printf("Error is null while attaching v4_0 connect prog.\n");
        return result;
    }
    printf("Attached program connect_4_0 to comp_id %d.\n", compartment_id);

    printf("Attach V6 connect prog.\n");
    bpf_prog_attach(bpf_program__fd(npm_ep.connect6_program), compartment_id, BPF_CGROUP_INET6_CONNECT, 0);
    if (result != 0)
    {
        printf("Error while attaching v6 connect prog\n");
        return result;
    }

    bpf_prog_attach(bpf_program__fd(npm_ep.recv4_accept_program), compartment_id, BPF_CGROUP_INET4_RECV_ACCEPT, 0);
    if (result != 0)
    {
        printf("Error is null while attaching v4 recv prog\n");
        return result;
    }
    printf("Attached program %s to comp_id %d", "recv_4.\n", compartment_id);

    printf("Attach V6 recv prog\n");
    bpf_prog_attach(bpf_program__fd(npm_ep.recv6_accept_program), compartment_id, BPF_CGROUP_INET6_RECV_ACCEPT, 0);
    if (result != 0)
    {
        printf("Error is null while attaching v6 recv prog\n");
        return result;
    }

    printf("Done attaching progs to compartment ID: %d\n", compartment_id);
}

fd_t create_comp_bpf_map()
{
    ebpf_map_type_t map_type = BPF_MAP_TYPE_HASH;
    int key_size = sizeof(policy_map_key_t);
    int value_size = sizeof(uint32_t);
    int max_entries = POLICY_MAP_SIZE;

    fd_t inner_map_fd =
        bpf_create_map(map_type, key_size, value_size, max_entries, 0);
    if (inner_map_fd < 0)
    {
        printf("FAILED creating the map\n");
        return INVALID_MAP_FD;
    }

    printf("create_comp_bpf_map: Created the map\n");
    return inner_map_fd;
}

fd_t get_map_fd(int internal_map_type, int compartment_id)
{
    char *map_name = NULL;
    get_epmap_name(internal_map_type, compartment_id, &map_name);
    if (map_name == NULL)
    {
        printf("Map name is null.\n");
        return INVALID_MAP_FD;
    }

    printf("get_map_fd: map name: %s\n", map_name);
    // Map fd is invalid. Open fd to the map.
    char *pin_path = get_map_pin_path(map_name);
    if (pin_path == NULL)
    {
        printf("get_map_fd: pin path is null\n");
        return INVALID_MAP_FD;
    }
    printf("get_map_fd: map pinned path %s\n", pin_path);
    fd_t fd = bpf_obj_get(pin_path);
    if (fd != INVALID_MAP_FD)
    {
        printf("get_map_fd: found the pinned map FD\n");
        return fd;
    }

    if (internal_map_type != COMP_POLICY_MAP)
    {
        printf("Fatal: no map fd is found!");
        return INVALID_MAP_FD;
    }

    printf("get_map_fd: pinned map not found, creating new comp policy map map %s\n", map_name);

    // Map not created yet. Create and pin the map.
    fd = create_comp_bpf_map();
    if (fd > 0)
    {
        // Map created. Now pin the map.
        int error = bpf_obj_pin(fd, pin_path);
        if (error != 0)
        {
            return INVALID_MAP_FD;
        }

        return fd;
    }

    printf("get_map_fd: failed to create the MAP\n");

    return INVALID_MAP_FD;
}

int update_global_policy_map(int compartment_id)
{
    fd_t compartment_policy_map_fd = get_map_fd(COMP_POLICY_MAP, compartment_id);
    if (compartment_policy_map_fd == INVALID_MAP_FD)
    {
        return -1;
    }

    fd_t global_policy_map_fd = get_map_fd(GLOBAL_POLICY_MAP, 0);
    if (global_policy_map_fd == INVALID_MAP_FD)
    {
        return INVALID_MAP_FD;
    }

    // Update the global policy map
    int error = bpf_map_update_elem(global_policy_map_fd, &compartment_id, &compartment_policy_map_fd, BPF_ANY);
    if (error != 0 && error != EEXIST)
    {
        printf("Error while updating global policy map\n");
        return error;
    }
    
    printf("Updated global policy map: com_id %d comp_map_fd %d", compartment_id, compartment_policy_map_fd);
    return 0;
}

int update_comp_policy_map(int remote_pod_label_id, direction_t direction, uint16_t remote_port, int compartment_id, int policy_id, bool delete)
{
    fd_t comp_policy_map_fd = get_map_fd(COMP_POLICY_MAP, compartment_id);
    if (comp_policy_map_fd == INVALID_MAP_FD)
    {
        return INVALID_MAP_FD;
    }
    policy_map_key_t key = {0};
    key.remote_pod_label_id = remote_pod_label_id;
    key.direction = direction;
    key.remote_port = htons(remote_port);
    key.protocol = 0;

    printf("Updating comp_policy_map for comp_id %d label %d dir %d port %d\n", 
        compartment_id, key.remote_pod_label_id, key.direction, key.remote_port);
    char* conv_key = (char*)&key;
    for (int i =0; i< sizeof(policy_map_key_t); ++i) {
        printf("%02x ", conv_key[i]);
        
    }
    printf("\n");
    
    if (!delete)
    {
        int result = bpf_map_update_elem(comp_policy_map_fd, &key, &policy_id, 0);
        if (result != 0)
        {
            printf("Error while updating comp policy map\n");
            return result;
        }
        int lookup_val;
        bpf_map_lookup_elem(comp_policy_map_fd, &key, &lookup_val);
        printf("looked up val %d", lookup_val);
    }
    else
    {
        int result = bpf_map_delete_elem(comp_policy_map_fd, &key);
        if (result != 0)
        {
            printf("Error while deleting comp policy map\n");
            return result;
        }
    }
    printf("Done updating comp policy map\n");
    return 0;
}

int update_ip_cache4(uint32_t ctx_label_id, uint32_t ipv4h, bool delete)
{
    int ipv4 = bpf_htonl(ipv4h);
    fd_t ip_cache_map_fd = get_map_fd(IP_CACHE_MAP, 0);

    if (ip_cache_map_fd == INVALID_MAP_FD)
    {
        printf("Invalid map fd %u", ip_cache_map_fd);
        return INVALID_MAP_FD;
    }

    ip_address_t ip_cache_key = {0};
    ip_cache_key.ipv4 = ipv4;

    if (!delete)
    {
        int result = bpf_map_update_elem(ip_cache_map_fd, &ip_cache_key, &ctx_label_id, 0);
        if (result != 0)
        {
            printf("Error while updating ip cache map %d\n", result);
            return result;
        }        

        uint32_t value = 0;
        bpf_map_lookup_elem(ip_cache_map_fd, &ip_cache_key, &value);
    }
    else
    {
        int result = bpf_map_delete_elem(ip_cache_map_fd, &ip_cache_key);
        if (result != 0)
        {
            printf("Error while deleting ip cache map\n");
            return result;
        }
    }

    ip_address_t key = {0};
    ip_address_t next_key = {0};
    uint32_t value = 0;

    int ret = _close(ip_cache_map_fd);
    printf("fd close res: %d\n", ret);

    printf("Done updating ip cache map\n");
    return 0;
}
