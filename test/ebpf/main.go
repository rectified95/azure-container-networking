package main

/*
#include <stdlib.h>
#include "testSockProg.h"
*/
import "C"
import (
	"encoding/binary"
	"fmt"
	"net"
)

type direction int

const (
	RET_ERR int       = -1
	INGRESS direction = 0
	EGRESS  direction = 1
)

func main() {
	res := initialize()
	if res == RET_ERR {
		fmt.Println("Error: Could not initialize sockprog")
		return
	}

}

func initialize() int {
	fmt.Println("init")
	r := (C.struct_npm_endpoint_prog_t)(C.test_ebpf_prog())

	if (r == C.struct_npm_endpoint_prog_t{}) {
		fmt.Print("failed to load")
		return RET_ERR
	}

	fmt.Println("%+v", r.connect4_program)

	fmt.Print("Done loading progs")
	fmt.Println(r)

	res := C.attach_progs(r)

	if res < 0 {
		return RET_ERR
	}

	return 0
}

func gupdate_comp_policy_map(remote_label_id, remote_port, policy_id, compartment_id int, dir direction, delete bool) int {
	res := C.update_comp_policy_map(
		C.int(remote_label_id),
		C.direction_t(dir),
		C.uint16_t(remote_port),
		C.int(compartment_id),
		C.int(policy_id),
		C.bool(delete),
	)
	if res < 0 {
		fmt.Println("Error: Could not update comp policy map")
		return RET_ERR
	}
	return 0
}

func gupdate_ip_cache(remote_label_id uint32, ip net.IP, delete bool) int {

	res := C.update_ip_cache4(C.uint32_t(remote_label_id), C.uint32_t(ip2int(ip)), C.bool(delete))
	if res < 0 {
		fmt.Println("Error: Could not update ip cache")
		return RET_ERR
	}
	return 0
}

func ip2int(ip net.IP) uint32 {
	if len(ip) == 16 {
		return binary.BigEndian.Uint32(ip[12:16])
	}
	return binary.BigEndian.Uint32(ip)
}
