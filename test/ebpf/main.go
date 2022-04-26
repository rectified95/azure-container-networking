package main

/*
#include <stdlib.h>
#include "testSockProg.h"
*/
import "C"
import "fmt"

func main() {
	r := C.test_ebpf_prog()

	if (r == C.struct_npm_endpoint_prog_t{}) {
		fmt.Print("failed to load")
		return
	}

	fmt.Print("Done loading progs")
	fmt.Println(r)

	res := C.attach_progs(r)
	fmt.Println(res)
}
