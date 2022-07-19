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

var winEbpfState *WinEbpfState

type WinEbpfState struct {
	epprog      C.struct_npm_endpoint_prog_t
	podMetadata map[string]int
}

func NewWinEbfState(epprog C.struct_npm_endpoint_prog_t) *WinEbpfState {
	return &WinEbpfState{
		epprog: epprog,
	}
}

func InitializeEbpfState() {
	fmt.Println("starting ebpf program")

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

	winEbpfState = winState

	// 85-testing cluster
	// block all traffic on pod with IP 10.240.0.47
	// "CompartmendId":  3,

	// frontend compid is 3
	// backend compid is 8
	// database compid is 4

	/*
		frontendID := 2
		databaseID := 3
		backendID := 4

		// attach to frontend endpoint id
		reErr := C.attach_progs_to_compartment(winState.epprog, C.int(frontendID))
		if reErr < 0 {
			fmt.Println("Failed while attaching prog to compartment %v with err %v", frontendID, reErr)
			return
		}

		reErr = C.attach_progs_to_compartment(winState.epprog, C.int(backendID))
		if reErr < 0 {
			fmt.Println("Failed while attaching prog to compartment %v with err %v", backendID, reErr)
			return
		}

		reErr = C.attach_progs_to_compartment(winState.epprog, C.int(databaseID))
		if reErr < 0 {
			fmt.Println("Failed while attaching prog to compartment %v with err %v", databaseID, reErr)
			return
		}

		fmt.Println("running our scenario")
		res1 := test_scenario(frontendID, backendID)
		if res1 < 0 {

			fmt.Println("Failed while running scenario")
			return
		}
	*/
}

func AttachProgsToCompartment(id int) error {
	reErr := C.attach_progs_to_compartment(winEbpfState.epprog, C.int(id))
	if reErr < 0 {
		fmt.Println("Failed while attaching prog to compartment %v with err %v", id, reErr)
		return fmt.Errorf("Failed while attaching prog to compartment %v with err %v", id, reErr)
	}
	return nil;
}

func CreateUpdateCompPolicyMap(id int) error {
	retCode := C.update_global_policy_map(C.int(id))
	if retCode < 0 {
		fmt.Println("Error: Could not get comp map fd")
		return fmt.Errorf("Error: Could not get comp map fd")
	}
	return nil;
}

func initialize() (*WinEbpfState, int) {
	fmt.Println("init")
	r := (C.struct_npm_endpoint_prog_t)(C.test_ebpf_prog())

	if (r == C.struct_npm_endpoint_prog_t{}) {
		fmt.Print("failed to load")
		return nil, RET_ERR
	}

	fmt.Println("%+v", r.connect4_0_program)
	fmt.Println("%+v", r.policy_eval_program)

	fmt.Print("Done loading progs")
	fmt.Println(r)

	state := NewWinEbfState(r)

	return state, 0
}

func UpdateIPCacheMap(ip string, id int) int {
	tempip := net.ParseIP(ip)
	if tempip == nil {
		fmt.Println("failed to parse ip %s", ip)
		return -1
	}

	err := gupdate_ip_cache(uint32(id), tempip, false)
	if err != 0 {
		fmt.Println("Error: Could not add to ip cache")
		return -1
	}
	return 0

}

func test_scenario(srcID, dstID int) int {

	iptoid := map[string]uint32{
		"10.240.0.56": 123, // backend
		"10.240.0.44": 456, // database
		"10.240.0.36": 789, // frontend
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

	retCode := C.update_global_policy_map(C.int(srcID))
	if retCode < 0 {
		fmt.Println("Error: Could not get comp map fd")
		return -1
	}

	retCode = C.update_global_policy_map(C.int(dstID))
	if retCode < 0 {
		fmt.Println("Error: Could not get comp map fd")
		return -1
	}

	retCode = C.update_global_policy_map(C.int(3))
	if retCode < 0 {
		fmt.Println("Error: Could not get comp map fd")
		return -1
	}

	// manually creating frotendpolicy id to 700
	// manually creating db policy with id 666
	// say compID is the frontend pod

	Gupdate_comp_policy_map(200, 443, 700, srcID, INGRESS, false) // allow ingress to frontend from anywhere on port 443
	Gupdate_comp_policy_map(200, 53, 700, srcID, EGRESS, false)   // allow egress from frontend to anywhere on port 53

	Gupdate_comp_policy_map(123, 443, 700, srcID, EGRESS, false)  // allow egress from frontend to backend on port 443 (map above)
	Gupdate_comp_policy_map(789, 443, 700, dstID, INGRESS, false) // allow ingress from frontend to backend on port 443

	Gupdate_comp_policy_map(123, 443, 666, 3, INGRESS, false)    // allow ingress from backend to db
	Gupdate_comp_policy_map(456, 443, 666, dstID, EGRESS, false) // allow egress from backend to db

	// need compartment policy map
	// create if doesn't exist policy map corresponding to frontendpolicy
	// add keys and action to policy map

	fmt.Println("All traffic should be dropped here")
	fmt.Println("Sleeping now")

	for i := 0; i <= 15; i++ {
		time.Sleep(1 * time.Minute)
		fmt.Println("Sleeping at %d min", i)
	}
	return 0
}

func Gupdate_comp_policy_map(remote_label_id, remote_port, policy_id, compartment_id int, dir direction, delete bool) int {
	fmt.Printf("Updating comp policy map with remote label: %d, remote port: %d, policy id: %d, compartment id: %d, direction: %s\n", remote_label_id, remote_port, policy_id, compartment_id, dir)
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
