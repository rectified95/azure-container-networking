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

func (dp *EBPF_DP) InsertPodID(id int, ip string) int {
	fmt.Println("Adding to IPcache %s, %s", ip, id)
	tempip := net.ParseIP(ip)
	delete := false
	res := C.update_ip_cache4(C.uint32_t(remote_label_id), C.uint32_t(convertip2int(ip)), C.bool(delete))
	if res < 0 {
		fmt.Println("Error: Could not update ip cache")
		return RET_ERR
	}
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


func convertip2int(ip net.IP) uint32 {
	if len(ip) == 16 {
		return binary.BigEndian.Uint32(ip[12:16])
	}
	return binary.BigEndian.Uint32(ip)
}