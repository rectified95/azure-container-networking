package main

/*
#include <stdlib.h>
#include "testSockProg.h"
*/
import "C"
import "fmt"

func main() {
	r := C.test_ebpf_prog()

	fmt.Println(r)
}
