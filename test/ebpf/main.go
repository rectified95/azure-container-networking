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
	"time"

	"github.com/Azure/azure-container-networking/common"
)

type direction int

const (
	COMP_POLICY_MAP = iota
	GLOBAL_POLICY_MAP
	IP_CACHE_MAP
)

const (
	RET_ERR          int       = -1
	INGRESS          direction = 0
	EGRESS           direction = 1
	AzureNetworkName           = "azure"
)

type WinEbpfState struct {
	epprog      C.struct_npm_endpoint_prog_t
	podMetadata map[string]int
}

func NewWinEbfState(epprog C.struct_npm_endpoint_prog_t) *WinEbpfState {
	return &WinEbpfState{
		epprog: epprog,
	}
}

func main() {

	ioShim := common.NewIOShim()

	network, err := ioShim.Hns.GetNetworkByName(AzureNetworkName)
	if err != nil {
		fmt.Println("Error: Could not get network, %s", err)
		return
	}

	endpoints, err := ioShim.Hns.ListEndpointsOfNetwork(network.Id)
	if err != nil {
		fmt.Println("Error: Could not get endpoints, %s", err)
		return
	}

	fmt.Println(endpoints)

	winState, res := initialize()
	if res == RET_ERR {
		fmt.Println("Error: Could not initialize sockprog")
		return
	}
	if winState == nil {
		fmt.Println("Failed to initialize WinEbpfState")
	}

	// 85-testing cluster
	// block all traffic on pod with IP 10.240.0.47
	// "CompartmendId":  3,

	compID := 3

	reErr := C.attach_progs_to_compartment(winState.epprog, C.int(compID))
	if reErr < 0 {
		fmt.Println("Failed while attaching prog to compartment")
		return
	}

	fmt.Println("running our scenario")
	res1 := test_scenario(compID)
	if res1 < 0 {

		fmt.Println("Failed while running scenario")
		return
	}

}

func initialize() (*WinEbpfState, int) {
	fmt.Println("init")
	r := (C.struct_npm_endpoint_prog_t)(C.test_ebpf_prog())

	if (r == C.struct_npm_endpoint_prog_t{}) {
		fmt.Print("failed to load")
		return nil, RET_ERR
	}

	fmt.Println("%+v", r.connect4_program)

	fmt.Print("Done loading progs")
	fmt.Println(r)

	state := NewWinEbfState(r)

	return state, 0
}

func test_scenario(compID int) int {

	iptoid := map[string]uint32{
		"10.240.0.16": 123,
		"10.240.0.41": 456,
		"10.240.0.15": 789,
	}

	for ip, id := range iptoid {
		fmt.Println("Adding to IPcache %s, %s", ip, id)
		tempip := net.ParseIP(ip)
		err := gupdate_ip_cache(id, tempip, false)
		if err != 0 {
			fmt.Println("Error: Could not add to ip cache")
			return -1
		}
	}

	retCode := C.update_global_policy_map(C.int(compID))
	if retCode < 0 {
		fmt.Println("Error: Could not get comp map fd")
		return -1
	}

	fmt.Println("All traffic should be dropped here")
	fmt.Println("Sleeping now")

	for i := 0; i <= 15; i++ {
		time.Sleep(1 * time.Minute)
		fmt.Println("Sleeping at %d min", i)
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
