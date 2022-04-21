int test_ebpf_prog();

struct npm_endpoint_prog_t
{
    bpf_program *connect4_program;
    bpf_program *connect6_program;
    bpf_program *recv4_accept_program;
    bpf_program *recv6_accept_program;
};

const char *connect4_program_name = "authorize_connect4";
const char *connect6_program_name = "authorize_connect6";
const char *recv4_accept_program_name = "authorize_recv_accept4";
const char *recv6_accept_program_name = "authorize_recv_accept6";