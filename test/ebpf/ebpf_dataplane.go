package ebpf

/*
#include <stdlib.h>
#include "testSockProg.h"
*/
import "C"
import (
	"encoding/binary"
	"fmt"
	"net"
	"time"

	"github.com/Azure/azure-container-networking/common"
)

type EBPF_DP struct {
	EPprog      C.struct_npm_endpoint_prog_t
	PodMetadata map[string]int

} 

func New() *EBPF_DP {
	return &EBPF_DP{}
}

func (dp *EBPF_DP) InitializeBPF() {
	r := (C.struct_npm_endpoint_prog_t)(C.test_ebpf_prog())

	if (r == C.struct_npm_endpoint_prog_t{}) {
		fmt.Print("failed to load")
		return nil, RET_ERR
	}

	fmt.Println("%+v", r.connect4_program)

	fmt.Print("Done loading progs")
	fmt.Println(r)
	dp.EPprog = r
}