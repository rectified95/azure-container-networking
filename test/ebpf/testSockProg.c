
#include <stdlib.h>
#include "bpf/bpf.h"
#include "bpf/libbpf.h"
#include "testSockProg.h"

struct npm_endpoint_prog_t test_ebpf_prog()
{
    const char *connect4_program_name = "authorize_connect4";
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
    printf("Loaded program\n");
    printf("%d program fd\n", program_fd);
    printf("%d result\n", result);

    if (result < 0 ) {        
        printf("Load program failed\n");
        return  _npm_endpoint_prog_t;
    }

    printf("Getting the bpf_prog for connect program\n");
    struct bpf_program *connect_program = bpf_object__find_program_by_name(object, connect4_program_name);
    if (!connect_program)
    {
        printf("%s is null\n", connect4_program_name);
        return _npm_endpoint_prog_t;
    }

    _npm_endpoint_prog_t.connect4_program = connect_program;
    printf("connect program\n");

    struct bpf_program *connect6_program = bpf_object__find_program_by_name(object, connect6_program_name);
    if (!connect6_program)
    {
        printf("%s is null\n", connect6_program_name);
        return _npm_endpoint_prog_t;
    }

    _npm_endpoint_prog_t.connect6_program = connect6_program;
    printf("connect6 program\n");

    struct bpf_program *recv_accept_program = bpf_object__find_program_by_name(object, recv4_accept_program_name);
    if (!recv_accept_program)
    {
        printf("%s is null\n", recv4_accept_program_name);
        return _npm_endpoint_prog_t;
    }

    _npm_endpoint_prog_t.recv4_accept_program = recv_accept_program;
    printf("recv program\n");

    struct bpf_program *recv6_accept_program = bpf_object__find_program_by_name(object, recv6_accept_program_name);
    if (!recv6_accept_program)
    {
        printf("%s is null\n", recv6_accept_program_name);
        return _npm_endpoint_prog_t;
    }

    _npm_endpoint_prog_t.recv4_accept_program = recv6_accept_program;
    printf("recv6 program\n");

    return _npm_endpoint_prog_t;
}

int attach_progs(struct npm_endpoint_prog_t npm_ep)
{
    printf("attaching progs\n");
    printf("attach V4 connect prog\n");
    // attach V4 connect prog
    int result = bpf_prog_attach(bpf_program__fd(npm_ep.connect4_program), 0, BPF_CGROUP_INET4_CONNECT, 0);
    if (result != 0)
    {
        printf("Error is null while attaching v4 connect prog\n");
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
