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

	fmt.Println("%+v", r.connect4_0_program)
	fmt.Println("%+v", r.policy_eval_program)

	fmt.Print("Done loading progs")
	fmt.Println(r)
	dp.EPprog = r
	return 0
}

/* commented out by matmerr, maybe needed?
func (dp *EBPF_DP) InsertPodID(id int, ip string) int {
	fmt.Println("Adding to IPcache %s, %s", ip, id)
	//tempip := net.ParseIP(ip)
	delete := false
	res := C.update_ip_cache4(C.uint32_t(remote_label_id), C.uint32_t(convertip2int(ip)), C.bool(delete))
	if res < 0 {
		fmt.Println("Error: Could not update ip cache")
		return RET_ERR
	}
	return 0
}
*/

func (dp *EBPF_DP) GetIDs() map[string]int {
	return map[string]int{
		"x:a":              150,
		"x:b":              151,
		"x:c":              152,
		"y:a":              160,
		"y:b":              161,
		"y:c":              162,
		"z:a":              170,
		"z:b":              171,
		"z:c":              172,
		"default:frontend": 180,
		"default:backend":  181,
		"default:database": 182,
		"any":              200,
	}
}

func convertip2int(ip net.IP) uint32 {
	if len(ip) == 16 {
		return binary.BigEndian.Uint32(ip[12:16])
	}
	return binary.BigEndian.Uint32(ip)
}

/*
func getFrontEndPolicyObj() {
	endpointPolicy := []C.struct_
	return

	```typedef struct policy_map_key
	{
		uint32_t remote_pod_label_id;
		// uint8_t protocol;  by default, we are using TCP protocol
		uint8_t direction;
		uint16_t remote_port;
	} policy_map_key_t;


	Podselector: role:frontend


	Policy Map of this role:frontend:

		Key= {
			remote_port: 443,
			remote_pod_label_id: 200,
			direction: IN
		}, 1 (policy ID),
		Key= {
			remote_port: 53,
			remote_pod_label_id: 200,
			direction: OUT
		}, 1 (policy ID),
	Key= {
		remote_port: 53,
		remote_pod_label_id: 180,
		direction: OUT
	}, 1 (policy ID),
	Key= {
		remote_port: 53,
		remote_pod_label_id: 181,
		direction: OUT
	}, 1 (policy ID),
	Key= {
		remote_port: 53,
		remote_pod_label_id: 182,
		direction: OUT
	}, 1 (policy ID),
	Key= {
		remote_port: 0,
		remote_pod_label_id: 180,
		direction: OUT
	}, 1 (policy ID),
		Key= {
			remote_port: 0,
			remote_pod_label_id: 181,
			direction: OUT
		}, 1 (policy ID),
	Key= {
		remote_port: 0,
		remote_pod_label_id: 182,
		direction: OUT
	}, 1 (policy ID),




	```
}

```
kind: NetworkPolicy
apiVersion: networking.k8s.io/v1
metadata:
  name: frontEndPolicy
spec:
  podSelector:
    matchLabels:
      role: frontend
  ingress:
  - ports:
    - port: 443
     - protocol: TCP
  egress:
  - ports:
    - port: 53
      protocol: UDP
    - port: 53
      protocol: TCP
  - to:
    - podSelector: {} # allow egress to all pods within the namespace.


---------------------------

kind: NetworkPolicy
apiVersion: networking.k8s.io/v1
metadata:
  name: backEndPolicy
spec:
  podSelector:
    matchLabels:
      role: backend
  ingress:
  - from:
      - podSelector:
          matchLabels:
            role: frontend
  egress:
  - ports:
    - port: 53
      protocol: UDP
    - port: 53
      protocol: TCP
  - to:
    - podSelector: {}


	Podselector: role:backend


	Policy Map of this role:backend:

	Key= {
		remote_port: 0,
		remote_pod_label_id: 180,
		direction: IN
	}, 2 (policy ID),
	Key= {
		remote_port: 53,
		remote_pod_label_id: 200,
		direction: OUT
	}, 2 (policy ID),
	Key= {
		remote_port: 53,
		remote_pod_label_id: 180,
		direction: OUT
	}, 2 (policy ID),
	Key= {
		remote_port: 53,
		remote_pod_label_id: 181,
		direction: OUT
	}, 2 (policy ID),
	Key= {
		remote_port: 53,
		remote_pod_label_id: 182,
		direction: OUT
	}, 2 (policy ID),
	Key= {
		remote_port: 0,
		remote_pod_label_id: 180,
		direction: OUT
	}, 2 (policy ID),
	Key= {
		remote_port: 0,
		remote_pod_label_id: 181,
		direction: OUT
	}, 2 (policy ID),
	Key= {
		remote_port: 0,
		remote_pod_label_id: 182,
		direction: OUT
	}, 2 (policy ID),

-----------------------
kind: NetworkPolicy
apiVersion: networking.k8s.io/v1
metadata:
  name: databasePolicy
spec:
  podSelector:
    matchLabels:
      role: database
  ingress:
  - from:
      - podSelector:
          matchLabels:
            role: backend
  egress: [] #all egress needs to be blocked cording to demo



  Podselector: role:database


  Policy Map of this role:database:

  Key= {
	  remote_port: 0,
	  remote_pod_label_id: 181,
	  direction: IN
  }, 3 (policy ID),


```
*/
