package dataplane

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os/exec"
	"strings"
	"sync"
	"time"

	"github.com/Azure/azure-container-networking/npm/pkg/dataplane/ipsets"
	"github.com/Azure/azure-container-networking/npm/pkg/dataplane/policies"
	"github.com/Azure/azure-container-networking/npm/util"
	ebpf "github.com/Azure/azure-container-networking/test/ebpf"
)

type Endpoints []struct {
	ID               string `json:"ID"`
	Name             string `json:"Name"`
	Version          int64  `json:"Version"`
	AdditionalParams struct {
	} `json:"AdditionalParams"`
	Resources struct {
		AdditionalParams struct {
		} `json:"AdditionalParams"`
		AllocationOrder int `json:"AllocationOrder"`
		Allocators      []struct {
			AdapterNetCfgInstanceID string `json:"AdapterNetCfgInstanceId,omitempty"`
			AdditionalParams        struct {
			} `json:"AdditionalParams"`
			AllocationOrder  int    `json:"AllocationOrder"`
			CompartmendID    int    `json:"CompartmendId,omitempty"`
			Connected        bool   `json:"Connected,omitempty"`
			DNSFirewallRules bool   `json:"DNSFirewallRules,omitempty"`
			DevicelessNic    bool   `json:"DevicelessNic,omitempty"`
			DhcpDisabled     bool   `json:"DhcpDisabled,omitempty"`
			EndpointNicGUID  string `json:"EndpointNicGuid,omitempty"`
			EndpointPortGUID string `json:"EndpointPortGuid,omitempty"`
			Flags            int    `json:"Flags"`
			Health           struct {
				LastErrorCode  int   `json:"LastErrorCode"`
				LastUpdateTime int64 `json:"LastUpdateTime"`
			} `json:"Health"`
			ID                        string `json:"ID"`
			InterfaceGUID             string `json:"InterfaceGuid,omitempty"`
			IsPolicy                  bool   `json:"IsPolicy"`
			IsolationID               int    `json:"IsolationId,omitempty"`
			Mtu                       int    `json:"MTU,omitempty"`
			MacAddress                string `json:"MacAddress,omitempty"`
			ManagementPort            bool   `json:"ManagementPort,omitempty"`
			NcfHidden                 bool   `json:"NcfHidden,omitempty"`
			NicFriendlyName           string `json:"NicFriendlyName,omitempty"`
			NlmHidden                 bool   `json:"NlmHidden,omitempty"`
			PreferredPortFriendlyName string `json:"PreferredPortFriendlyName,omitempty"`
			State                     int    `json:"State"`
			SwitchID                  string `json:"SwitchId,omitempty"`
			Tag                       string `json:"Tag"`
			WaitForIpv6Interface      bool   `json:"WaitForIpv6Interface,omitempty"`
			NonPersistentPort         bool   `json:"nonPersistentPort,omitempty"`
			IcmpNatPool               string `json:"IcmpNatPool,omitempty"`
			IsIpv6                    bool   `json:"IsIpv6,omitempty"`
			LocalRoutedVip            bool   `json:"LocalRoutedVip,omitempty"`
			NatExceptions0            string `json:"NatExceptions_0,omitempty"`
			NatExceptions1            string `json:"NatExceptions_1,omitempty"`
			NatExceptions2            string `json:"NatExceptions_2,omitempty"`
			TCPNatPool                string `json:"TcpNatPool,omitempty"`
			UDPNatPool                string `json:"UdpNatPool,omitempty"`
			Vip                       string `json:"VIP,omitempty"`
			AutomaticEndpointMonitor  bool   `json:"AutomaticEndpointMonitor,omitempty"`
			DestinationPrefix         string `json:"DestinationPrefix,omitempty"`
			NeedEncap                 bool   `json:"NeedEncap,omitempty"`
			NextHop                   string `json:"NextHop,omitempty"`
			Rules                     []struct {
				ID         string `json:"Id"`
				Name       string `json:"Name"`
				PolicyType string `json:"PolicyType"`
				Type       string `json:"Type"`
				Values     string `json:"Values"`
			} `json:"Rules,omitempty"`
			IsNetworkACL bool `json:"IsNetworkACL,omitempty"`
		} `json:"Allocators"`
		CompartmentOperationTime int `json:"CompartmentOperationTime"`
		Flags                    int `json:"Flags"`
		Health                   struct {
			LastErrorCode  int   `json:"LastErrorCode"`
			LastUpdateTime int64 `json:"LastUpdateTime"`
		} `json:"Health"`
		ID                  string `json:"ID"`
		PortOperationTime   int    `json:"PortOperationTime"`
		State               int    `json:"State"`
		SwitchOperationTime int    `json:"SwitchOperationTime"`
		VfpOperationTime    int    `json:"VfpOperationTime"`
		ParentID            string `json:"parentId"`
	} `json:"Resources"`
	State              int    `json:"State"`
	VirtualNetwork     string `json:"VirtualNetwork"`
	VirtualNetworkName string `json:"VirtualNetworkName"`
	Policies           []struct {
		ExceptionList     []string `json:"ExceptionList,omitempty"`
		Type              string   `json:"Type"`
		DestinationPrefix string   `json:"DestinationPrefix,omitempty"`
		NeedEncap         bool     `json:"NeedEncap,omitempty"`
		Action            string   `json:"Action,omitempty"`
		Direction         string   `json:"Direction,omitempty"`
		Priority          int      `json:"Priority,omitempty"`
		Protocols         string   `json:"Protocols,omitempty"`
		RemoteAddresses   string   `json:"RemoteAddresses,omitempty"`
		RemotePorts       string   `json:"RemotePorts,omitempty"`
		RuleType          string   `json:"RuleType,omitempty"`
		Scope             int      `json:"Scope,omitempty"`
	} `json:"Policies"`
	MacAddress     string `json:"MacAddress"`
	IPAddress      string `json:"IPAddress"`
	PrefixLength   int    `json:"PrefixLength,omitempty"`
	GatewayAddress string `json:"GatewayAddress,omitempty"`
	IPSubnetID     string `json:"IPSubnetId,omitempty"`
	DNSServerList  string `json:"DNSServerList"`
	DNSSuffix      string `json:"DNSSuffix"`
	DNSDomain      string `json:"DNSDomain"`
	Namespace      struct {
		ID string `json:"ID"`
	} `json:"Namespace,omitempty"`
	EncapOverhead    int      `json:"EncapOverhead"`
	SharedContainers []string `json:"SharedContainers"`
	IsRemoteEndpoint bool     `json:"IsRemoteEndpoint,omitempty"`
}

type CompartmentInfo struct {
	PodMetadata       PodMetadata
	CompartmentID     int
	EbpfRemoteLabelID int
}

func GetRemoteLabelID(podname string) int {
	switch {
	case strings.Contains(podname, "frontend"):
		return 123
	case strings.Contains(podname, "backend"):
		return 456
	case strings.Contains(podname, "database"):
		return 789
	default:
		return 0
	}
}

func BuildCompartmentInfo(pm PodMetadata) (*CompartmentInfo, error) {
	cmd := exec.Command("powershell", "-nologo", "-noprofile", "Get-hnsendpoint | Convertto-json -Depth 20")

	out, err := cmd.CombinedOutput()
	if err != nil {
		log.Fatal(err)
	}
	eps := Endpoints{}
	json.Unmarshal([]byte(out), &eps)

	compartmentinfo := CompartmentInfo{
		PodMetadata:       pm,
		EbpfRemoteLabelID: GetRemoteLabelID(pm.PodKey),
	}

	for _, ep := range eps {
		if ep.IPAddress == pm.PodIP {

			for _, alloc := range ep.Resources.Allocators {
				if alloc.CompartmendID != 0 {
					compartmentinfo.CompartmentID = alloc.CompartmendID
				}
			}
			return &compartmentinfo, nil
		}
	}
	return &compartmentinfo, fmt.Errorf("no endpoint found with IP %s", pm.PodIP)
}

// podkey = default/podname
// podname = podname
func (e *EbpfDataplane) GetCompartmentInfoFromPodname(podname string) ([]*CompartmentInfo, error) {
	e.RLock()
	defer e.RUnlock()

	//var comps []*CompartmentInfo
	comps := []*CompartmentInfo{}

	for k, v := range e.iptocompartment {
		if strings.Contains(v.PodMetadata.PodKey, podname) {
			comps = append(comps, e.iptocompartment[k])
			//return e.iptocompartment[k], nil
		}
	}

	// if strings.Contains(podname, "backend") {
	// 	if (len(comps) == 2) {
	// 		return comps, nil
	// 	}	
	// }
	if (len(comps) != 0) {
		return comps, nil
	}

	return nil, fmt.Errorf("CompartmentInfo not found for name %s", podname)
}

type EbpfDataplane struct {
	sync.RWMutex
	iptocompartment map[string]*CompartmentInfo
}

func NewEbpfDataplane(config *Config) *EbpfDataplane {
	log.Printf("starting dataplane")
	dp := &EbpfDataplane{
		iptocompartment: map[string]*CompartmentInfo{},
	}
	dp.BootupDataplane()
	return dp
}

func (e *EbpfDataplane) BootupDataplane() error {
	log.Printf("[ebpf] BootupDataplane")

	// uncomment this when ready
	ebpf.InitializeEbpfState()
	return nil
}

func (e *EbpfDataplane) RunPeriodicTasks() {
	log.Printf("[ebpf] RunPeriodicTasks")
}

func (e *EbpfDataplane) GetAllIPSets() map[string]string {
	log.Printf("[ebpf] GetAllIPSets")
	return nil
}

func (e *EbpfDataplane) GetIPSet(setName string) *ipsets.IPSet {
	log.Printf("[ebpf] GetIPSet: %s", setName)
	return nil
}

func (e *EbpfDataplane) CreateIPSets(setMetadatas []*ipsets.IPSetMetadata) {
	log.Printf("[ebpf] CreateIPSets: %+v", setMetadatas)
	for _, metadata := range setMetadatas {
		log.Printf("\t set metadata: %+v\n", metadata)
	}
}

func (e *EbpfDataplane) DeleteIPSet(setMetadata *ipsets.IPSetMetadata, deleteOption util.DeleteOption) {
	log.Printf("[ebpf] DeleteIPSet: %+v, DeleteOption %v", setMetadata, deleteOption)
}

func (e *EbpfDataplane) AddToSets(setMetadatas []*ipsets.IPSetMetadata, podMetadata *PodMetadata) error {
	// we haven't seen this pod before, save and attach
	e.Lock()
	defer e.Unlock()
	compartment := e.iptocompartment[podMetadata.PodIP]

	if compartment == nil {
		var err error
		compartment, err = BuildCompartmentInfo(*podMetadata)
		if err != nil {
			log.Printf("[ebpf] failed to get local compartment with err %v", err)
		}
		log.Printf("[ebpf] AddToSets: Compartment ID:%d, %+v", compartment.CompartmentID, podMetadata)

		e.iptocompartment[podMetadata.PodIP] = compartment

		if compartment.EbpfRemoteLabelID != 0 {
			// attach ebpf program to compartment
			// uncomment this when ready
			log.Printf("[ebpf] attaching program to compartment id %d", compartment.CompartmentID)
			ebpf.AttachProgsToCompartment(compartment.CompartmentID)
			if compartment.EbpfRemoteLabelID != 0 {
				ebpf.UpdateIPCacheMap(compartment.PodMetadata.PodIP, compartment.EbpfRemoteLabelID)
			}
		} else {
			log.Printf("[ebpf] skipping attach programs to %+v", podMetadata)
		}

	}
	return nil
}

func (e *EbpfDataplane) RemoveFromSets(setMetadatas []*ipsets.IPSetMetadata, podMetadata *PodMetadata) error {
	log.Printf("[ebpf] RemoveFromSets: %+v, %+v", setMetadatas, podMetadata)
	for _, metadata := range setMetadatas {
		log.Printf("\t set metadata: %+v\n", metadata)
	}
	return nil
}

func (e *EbpfDataplane) AddToLists(listMetadatas []*ipsets.IPSetMetadata, setMetadatas []*ipsets.IPSetMetadata) error {
	log.Printf("[ebpf] AddToLists: %+v, %+v", listMetadatas, setMetadatas)
	for _, metadata := range setMetadatas {
		log.Printf("\t list metadata: %+v\n", metadata)
	}
	return nil
}

func (e *EbpfDataplane) RemoveFromList(listMetadata *ipsets.IPSetMetadata, setMetadatas []*ipsets.IPSetMetadata) error {
	log.Printf("[ebpf] RemoveFromList: %+v, %+v", listMetadata, setMetadatas)
	for _, metadata := range setMetadatas {
		log.Printf("\t set metadata: %+v\n", metadata)
	}
	return nil
}

func (e *EbpfDataplane) ApplyDataPlane() error {
	log.Printf("[ebpf] ApplyDataPlane")
	e.RLock()
	b, err := json.MarshalIndent(e.iptocompartment, "", "  ")
	e.RUnlock()
	if err != nil {
		fmt.Println("error:", err)
	}
	fmt.Print(string(b))
	return nil
}

func (e *EbpfDataplane) GetAllPolicies() []string {
	log.Printf("[ebpf] GetAllPolicies")
	return nil
}

func (e *EbpfDataplane) AddPolicy(policies *policies.NPMNetworkPolicy) error {
	log.Printf("[ebpf] AddPolicy: %+v", policies)
	return nil
}

func (e *EbpfDataplane) RemovePolicy(PolicyKey string) error {
	log.Printf("[ebpf] RemovePolicy: %s", PolicyKey)
	return nil
}

func (e *EbpfDataplane) UpdatePolicy(policies *policies.NPMNetworkPolicy) error {
	log.Printf("[ebpf] UpdatePolicy: %+v", policies)

	podnames := []string{
		"frontend",
		"backend",
		"database",
	}

	policyID := map[string]int{
		"frontendpolicy": 111,
		"backendpolicy":  222,
		"databasepolicy": 333,
	}

	ensureAllPodsExist := func() error {
		for _, podname := range podnames {
			_, err := e.GetCompartmentInfoFromPodname(podname)
			if err != nil {
				fmt.Printf("[ebpf] Updatepolicy failed to get compartment with err: %v\n", err)
				return err
			}
		}
		return nil
	}

	retrier := Retrier{Attempts: 20, Delay: 1 * time.Second}
	retrier.Do(context.Background(), ensureAllPodsExist)

	frontendpod, _ := e.GetCompartmentInfoFromPodname("frontend")
	backendpod, _ := e.GetCompartmentInfoFromPodname("backend")
	databasepod, _ := e.GetCompartmentInfoFromPodname("database")

	//fmt.Printf("UpdatePolicy: frontend: %+v, backend: %+v\n", frontendpod, backendpod)

	allowAll := 200

	if strings.Contains(policies.PolicyKey, "frontendpolicy") {
		if frontendpod != nil {
			for _, frontend := range frontendpod { 
				if (frontend != nil) {

					ebpf.Gupdate_comp_policy_map(allowAll, 80, policyID["frontendpolicy"], frontend.CompartmentID, ebpf.EGRESS, false) // frontend can ping anywhere
					//ebpf.Gupdate_comp_policy_map(allowAll, 80, policyID["frontendpolicy"], frontendpod.CompartmentID, ebpf.INGRESS, false) // allow ingress to frontend from anywhere on port 443
					ebpf.Gupdate_comp_policy_map(allowAll, 53, policyID["frontendpolicy"], frontend.CompartmentID, ebpf.EGRESS, false)  // allow egress from frontend to anywhere on port 53
				}
			}
		}

		if backendpod != nil && frontendpod != nil {
			for _, backend := range backendpod {
				for _, frontend := range frontendpod {
					if (frontend != nil && backend != nil) {
						fmt.Printf("UpdatePolicy: frontend: %+v, backend: %+v\n", frontend, backend)
						ebpf.Gupdate_comp_policy_map(backend.EbpfRemoteLabelID, 80, policyID["frontendpolicy"], frontend.CompartmentID, ebpf.EGRESS, false)      // allow egress from frontend to backend on port 443 (map above)
						ebpf.Gupdate_comp_policy_map(frontend.EbpfRemoteLabelID, 80, policyID["frontendpolicy"], backend.CompartmentID, ebpf.INGRESS, false) // allow ingress from frontend to backend on port 443
					}
				}
			}
		}
	}

	if strings.Contains(policies.PolicyKey, "backendpolicy") {

	}

	if strings.Contains(policies.PolicyKey, "databasepolicy") {
		if backendpod != nil && databasepod != nil {
			for _, backend := range backendpod {
				for _, database := range databasepod {
					if backend != nil && database != nil {
						fmt.Printf("UpdatePolicy: backend: %+v, database: %+v\n", backend, database)
						ebpf.Gupdate_comp_policy_map(backend.EbpfRemoteLabelID, 80, policyID["databasepolicy"], database.CompartmentID, ebpf.INGRESS, false) // allow ingress to frontend from anywhere on port 443
						ebpf.Gupdate_comp_policy_map(database.EbpfRemoteLabelID, 80, policyID["databasepolicy"], backend.CompartmentID, ebpf.EGRESS, false)  // allow ingress to frontend from anywhere on port 443
					}
				}
			}
		}

	}

	return nil
}

// copypaste from integration suite
// a Retrier can attempt an operation multiple times, based on some thresholds
type Retrier struct {
	Attempts   int
	Delay      time.Duration
	ExpBackoff bool
}

func (r Retrier) Do(ctx context.Context, f func() error) error {
	done := make(chan struct{})
	var err error
	go func() {
		defer func() { done <- struct{}{} }()
		for i := 0; i < r.Attempts; i++ {
			err = f()
			if err == nil {
				break
			}
			time.Sleep(r.Delay)
			if r.ExpBackoff {
				r.Delay *= 2
			}
		}
	}()

	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-done:
		return err
	}
}
