
#include <stdlib.h>
#include "bpf/bpf.h"
#include "bpf/libbpf.h"

typedef struct bpf_object go_bpf_obj;
npm_endpoint_prog_t test_ebpf_prog()
{
    struct npm_endpoint_prog_t _npm_endpoint_prog_t;
    struct bpf_object *object;
    int program_fd;
    int result = bpf_prog_load("cgroup_sock_addr.o", BPF_PROG_TYPE_CGROUP_SOCK_ADDR, &object, &program_fd);

    if (!object)
    {
        printf("object is null\n");
        return NULL;
    }
    printf("Loaded program\n");
    printf("%d program fd \n", program_fd);
    printf("%d result \n", result);

    printf("Getting the bpf_prog for connect program\n");
    bpf_program *connect_program = bpf_object__find_program_by_name(object, connect4_program_name);
    if (!connect_program)
    {
        printf("%s is null\n", connect4_program_name);
        return NULL;
    }

    _npm_endpoint_prog_t.connect4_program = connect_program;

    bpf_program *connect6_program = bpf_object__find_program_by_name(object, connect6_program_name);
    if (!connect6_program)
    {
        printf("%s is null\n", connect6_program_name);
        return NULL;
    }

    _npm_endpoint_prog_t.connect6_program = connect6_program;

    bpf_program *recv_accept_program = bpf_object__find_program_by_name(object, recv4_accept_program_name);
    if (!recv_accept_program)
    {
        printf("%s is null\n", recv4_accept_program_name);
        return NULL;
    }

    _npm_endpoint_prog_t.recv4_accept_program = recv_accept_program;

    bpf_program *recv6_accept_program = bpf_object__find_program_by_name(object, recv6_accept_program_name);
    if (!recv6_accept_program)
    {
        printf("%s is null\n", recv6_accept_program_name);
        return NULL;
    }

    _npm_endpoint_prog_t.recv4_accept_program = recv6_accept_program;

    return _npm_endpoint_prog_t;
}