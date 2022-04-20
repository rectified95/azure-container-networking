package main

/*
#include <stdlib.h>
#include "bpf/bpf.h"
#include "bpf/libbpf.h"

typedef struct bpf_object go_bpf_obj;
int test_ebpf_prog() {
	FILE* ptr;
    char ch;

    // Opening file in reading mode
    ptr = fopen("cgroup_sock_addr.o", "r");

    if (NULL == ptr) {
        printf("file can't be opened \n");
    }

    printf("content of this file are \n");

    // Printing what is written in file
    // character by character using loop.
    do {
        ch = fgetc(ptr);
        printf("%c", ch);

        // Checking if character is not EOF.
        // If it is EOF stop eading.
    } while (ch != EOF);

    // Closing the file
    fclose(ptr);


    struct bpf_object* object;
    int program_fd;
    int result = bpf_prog_load("cgroup_sock_addr.o", BPF_PROG_TYPE_CGROUP_SOCK_ADDR, &object, &program_fd);

	if (!object) {
		printf("object is not null\n");
	}
	else {
		printf("Loaded program\n");
		printf("%d program fd \n", program_fd);
	}

	printf("%d result \n", result);

	return result;
}
*/
import "C"
import "fmt"

func main() {
	r := C.test_ebpf_prog()

	fmt.Println(r)
}
