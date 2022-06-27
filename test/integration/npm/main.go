package main

import (
	"fmt"
	"time"

	"github.com/Azure/azure-container-networking/common"
	"github.com/Azure/azure-container-networking/npm/pkg/dataplane"
	"github.com/Azure/azure-container-networking/npm/pkg/dataplane/ipsets"
	"github.com/Azure/azure-container-networking/npm/pkg/dataplane/policies"
	"github.com/Azure/azure-container-networking/npm/util"
)

const (
	MaxSleepTime            = 1
	finalSleepTimeInSeconds = 10
	includeLists            = false
)

var (
	counter = 0

	dpCfg = &dataplane.Config{
		IPSetManagerCfg: &ipsets.IPSetManagerCfg{
			IPSetMode:   ipsets.ApplyAllIPSets,
			NetworkName: "azure",
		},
		PolicyManagerCfg: &policies.PolicyManagerCfg{
			PolicyMode:           policies.IPSetPolicyMode,
			PlaceAzureChainFirst: util.PlaceAzureChainFirst,
		},
	}

	nodeName   = "testNode"
	testNetPol = &policies.NPMNetworkPolicy{
		PolicyKey:   "test/test-netpol",
		Namespace:   "test",
		ACLPolicyID: "azure-acl-test-netpol",
		PodSelectorIPSets: []*ipsets.TranslatedIPSet{
			{
				Metadata: ipsets.TestNSSet.Metadata,
			},
			{
				Metadata: ipsets.TestKeyPodSet.Metadata,
			},
		},
		RuleIPSets: []*ipsets.TranslatedIPSet{
			{
				Metadata: ipsets.TestNSSet.Metadata,
			},
			{
				Metadata: ipsets.TestKeyPodSet.Metadata,
			},
		},
		ACLs: []*policies.ACLPolicy{
			{
				Target:    policies.Dropped,
				Direction: policies.Ingress,
			},
			{
				Target:    policies.Allowed,
				Direction: policies.Ingress,
				SrcList: []policies.SetInfo{
					{
						IPSet:     ipsets.TestNSSet.Metadata,
						Included:  true,
						MatchType: policies.SrcMatch,
					},
					{
						IPSet:     ipsets.TestKeyPodSet.Metadata,
						Included:  true,
						MatchType: policies.SrcMatch,
					},
				},
			},
		},
	}
)

func main() {
	dp, err := dataplane.NewDataPlane(nodeName, common.NewIOShim(), dpCfg, make(chan struct{}, 1))
	panicOnError(err)
	dp.RunPeriodicTasks()
	printAndWait(true)

	podMetadata := &dataplane.PodMetadata{
		PodKey:   "a",
		PodIP:    "10.0.0.0",
		NodeName: "",
	}

	// add all types of ipsets, some with members added
	panicOnError(dp.AddToSets([]*ipsets.IPSetMetadata{ipsets.TestNSSet.Metadata}, podMetadata))
	podMetadataB := &dataplane.PodMetadata{
		PodKey:   "b",
		PodIP:    "10.0.0.1",
		NodeName: "",
	}
	panicOnError(dp.AddToSets([]*ipsets.IPSetMetadata{ipsets.TestNSSet.Metadata}, podMetadataB))
	podMetadataC := &dataplane.PodMetadata{
		PodKey:   "c",
		PodIP:    "10.240.0.83",
		NodeName: nodeName,
	}
	panicOnError(dp.AddToSets([]*ipsets.IPSetMetadata{ipsets.TestKeyPodSet.Metadata, ipsets.TestNSSet.Metadata}, podMetadataC))
	dp.CreateIPSets([]*ipsets.IPSetMetadata{ipsets.TestKVPodSet.Metadata, ipsets.TestNamedportSet.Metadata, ipsets.TestCIDRSet.Metadata})

	panicOnError(dp.ApplyDataPlane())

	printAndWait(true)

	if includeLists {
		panicOnError(dp.AddToLists([]*ipsets.IPSetMetadata{ipsets.TestKeyNSList.Metadata, ipsets.TestKVNSList.Metadata}, []*ipsets.IPSetMetadata{ipsets.TestNSSet.Metadata}))

		panicOnError(dp.AddToLists([]*ipsets.IPSetMetadata{ipsets.TestNestedLabelList.Metadata}, []*ipsets.IPSetMetadata{ipsets.TestKVPodSet.Metadata, ipsets.TestKeyPodSet.Metadata}))
	}

	// remove members from some sets and delete some sets
	panicOnError(dp.RemoveFromSets([]*ipsets.IPSetMetadata{ipsets.TestNSSet.Metadata}, podMetadataB))
	podMetadataD := &dataplane.PodMetadata{
		PodKey:   "d",
		PodIP:    "1.2.3.4",
		NodeName: "",
	}
	panicOnError(dp.AddToSets([]*ipsets.IPSetMetadata{ipsets.TestKeyPodSet.Metadata, ipsets.TestNSSet.Metadata}, podMetadataD))
	dp.DeleteIPSet(ipsets.TestKVPodSet.Metadata, util.SoftDelete)
	panicOnError(dp.ApplyDataPlane())

	if includeLists {
		panicOnError(dp.AddToLists([]*ipsets.IPSetMetadata{ipsets.TestNestedLabelList.Metadata}, []*ipsets.IPSetMetadata{ipsets.TestKVPodSet.Metadata, ipsets.TestNSSet.Metadata}))
	}

	printAndWait(true)
	panicOnError(dp.RemoveFromSets([]*ipsets.IPSetMetadata{ipsets.TestNSSet.Metadata}, podMetadata))

	dp.DeleteIPSet(ipsets.TestNSSet.Metadata, util.SoftDelete)
	panicOnError(dp.ApplyDataPlane())
	printAndWait(true)

	panicOnError(dp.AddPolicy(testNetPol))
	printAndWait(true)

	panicOnError(dp.RemovePolicy(testNetPol.PolicyKey))
	printAndWait(true)

	panicOnError(dp.AddPolicy(testNetPol))
	printAndWait(true)

	podMetadataD = &dataplane.PodMetadata{
		PodKey:   "d",
		PodIP:    "10.240.0.91",
		NodeName: nodeName,
	}
	panicOnError(dp.AddToSets([]*ipsets.IPSetMetadata{ipsets.TestKeyPodSet.Metadata, ipsets.TestNSSet.Metadata}, podMetadataD))
	panicOnError(dp.ApplyDataPlane())
	printAndWait(true)

	panicOnError(dp.RemovePolicy(testNetPol.PolicyKey))
	panicOnError(dp.AddPolicy(policies.TestNetworkPolicies[0]))
	panicOnError(dp.AddPolicy(policies.TestNetworkPolicies[1]))
	printAndWait(true)

	panicOnError(dp.RemovePolicy(policies.TestNetworkPolicies[2].PolicyKey)) // no-op
	panicOnError(dp.AddPolicy(policies.TestNetworkPolicies[2]))
	printAndWait(true)

	// remove all policies. For linux, iptables should reboot if the policy manager config specifies so
	panicOnError(dp.RemovePolicy(policies.TestNetworkPolicies[0].PolicyKey))
	panicOnError(dp.RemovePolicy(policies.TestNetworkPolicies[1].PolicyKey))
	panicOnError(dp.RemovePolicy(policies.TestNetworkPolicies[2].PolicyKey))
	fmt.Println("there should be no rules in AZURE-NPM right now.")
	printAndWait(true)
	panicOnError(dp.AddPolicy(policies.TestNetworkPolicies[0]))
	fmt.Println("AZURE-NPM should have rules now")
	printAndWait(true)

	unusedSet1 := ipsets.NewIPSetMetadata("unused-set1", ipsets.CIDRBlocks)
	fmt.Printf("\ncreating an empty set, it should be deleted by reconcile: %s\n", unusedSet1.GetHashedName())
	dp.CreateIPSets([]*ipsets.IPSetMetadata{unusedSet1})
	panicOnError(dp.ApplyDataPlane())

	fmt.Printf("sleeping %d seconds to allow reconcile (update the reconcile time in dataplane.go to be less than %d seconds)\n", finalSleepTimeInSeconds, finalSleepTimeInSeconds)
	time.Sleep(time.Duration(finalSleepTimeInSeconds) * time.Second)

	unusedSet2 := ipsets.NewIPSetMetadata("unused-set2", ipsets.CIDRBlocks)
	fmt.Printf("\ncreating an unused set %s. The prior empty set %s should be deleted on this apply\n", unusedSet2.GetHashedName(), unusedSet1.GetHashedName())
	dp.CreateIPSets([]*ipsets.IPSetMetadata{unusedSet2})
	panicOnError(dp.ApplyDataPlane())

}

func panicOnError(err error) {
	if err != nil {
		panic(err)
	}
}

func printAndWait(wait bool) {
	counter++
	fmt.Printf("#####################\nCompleted running step %d, please check relevant commands, script will resume in %d secs\n#############\n", counter, MaxSleepTime)
	if wait {
		for i := 0; i < MaxSleepTime; i++ {
			fmt.Print(".")
			time.Sleep(time.Second)
		}
	}
}
