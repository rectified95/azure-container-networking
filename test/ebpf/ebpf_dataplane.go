package ebpf

/*
#include <stdlib.h>
#include "testSockProg.h"
*/
import "C"
import (
	"fmt"
)

type EBPF_DP struct {
	EPprog      C.struct_npm_endpoint_prog_t
	PodMetadata map[string]int
}

func New() *EBPF_DP {
	return &EBPF_DP{}
}

func (dp *EBPF_DP) InitializeBPF() int {
	r := (C.struct_npm_endpoint_prog_t)(C.test_ebpf_prog())

	if (r == C.struct_npm_endpoint_prog_t{}) {
		fmt.Print("failed to load")
		return RET_ERR
	}

	fmt.Println("%+v", r.connect4_program)

	fmt.Print("Done loading progs")
	fmt.Println(r)
	dp.EPprog = r
	return 0
}

func (dp *EBPF_DP) GetIDs() map[string]int {
	return map[string]int{
		"x:a": 150,
		"x:b": 151,
		"x:c": 152,
		"y:a": 160,
		"y:b": 161,
		"y:c": 162,
		"z:a": 170,
		"z:b": 171,
		"z:c": 172,
		"any": 200,
	}
}
