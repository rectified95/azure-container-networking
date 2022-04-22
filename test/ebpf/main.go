package main

/*
#include <stdlib.h>
#include "testSockProg.h"
*/
import "C"
import "fmt"

// go:generate go run github.com/cilium/ebpf/cmd/bpf2go foo src\cgroup_sock_addr.c -- -IC:\Users\azureuser\ebpf-for-windows\include
func main() {
	r := C.test_ebpf_prog()

	fmt.Println(r)
}
