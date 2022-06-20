package dataplane

import (
	"log"

	"github.com/Azure/azure-container-networking/npm/pkg/dataplane/ipsets"
	"github.com/Azure/azure-container-networking/npm/pkg/dataplane/policies"
	"github.com/Azure/azure-container-networking/npm/util"
)

type EbpfDataplane struct{}

func NewEbpfDataplane(config *Config) *EbpfDataplane {
	return &EbpfDataplane{}
}

func (e *EbpfDataplane) BootupDataplane() error {
	log.Printf("[ebpf] BootupDataplane")
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
}

func (e *EbpfDataplane) DeleteIPSet(setMetadata *ipsets.IPSetMetadata, deleteOption util.DeleteOption) {
	log.Printf("[ebpf] DeleteIPSet: %+v, DeleteOption %v", setMetadata, deleteOption)
}

func (e *EbpfDataplane) AddToSets(setMetadatas []*ipsets.IPSetMetadata, podMetadata *PodMetadata) error {
	log.Printf("[ebpf] AddToSets: %+v, %+v", setMetadatas, podMetadata)
	return nil
}

func (e *EbpfDataplane) RemoveFromSets(setMetadatas []*ipsets.IPSetMetadata, podMetadata *PodMetadata) error {
	log.Printf("[ebpf] RemoveFromSets: %+v, %+v", setMetadatas, podMetadata)
	return nil
}

func (e *EbpfDataplane) AddToLists(listMetadatas []*ipsets.IPSetMetadata, setMetadatas []*ipsets.IPSetMetadata) error {
	log.Printf("[ebpf] AddToLists: %+v, %+v", listMetadatas, setMetadatas)
	return nil
}

func (e *EbpfDataplane) RemoveFromList(listMetadata *ipsets.IPSetMetadata, setMetadatas []*ipsets.IPSetMetadata) error {
	log.Printf("[ebpf] RemoveFromList: %+v, %+v", listMetadata, setMetadatas)
	return nil
}

func (e *EbpfDataplane) ApplyDataPlane() error {
	log.Printf("[ebpf] ApplyDataPlane")
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
	return nil
}
