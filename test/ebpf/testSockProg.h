#include <stdlib.h>
#include "bpf/bpf.h"
#include "bpf/libbpf.h"

struct npm_endpoint_prog_t test_ebpf_prog();


typedef struct bpf_object go_bpf_obj;


struct npm_endpoint_prog_t
{
    struct bpf_program *connect4_program;
    struct bpf_program *connect6_program;
    struct bpf_program *recv4_accept_program;
    struct bpf_program *recv6_accept_program;
};