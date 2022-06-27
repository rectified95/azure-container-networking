package policies

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/Microsoft/hcsshim/hcn"
	"k8s.io/klog"
)

var (
	ErrFailedMarshalACLSettings                      = errors.New("Failed to marshal ACL settings")
	ErrFailedUnMarshalACLSettings                    = errors.New("Failed to unmarshal ACL settings")
	resetAllACLs                  shouldResetAllACLs = true
	removeOnlyGivenPolicy         shouldResetAllACLs = false
)

type staleChains struct{} // unused in Windows

type shouldResetAllACLs bool

type endpointPolicyBuilder struct {
	aclPolicies   []*NPMACLPolSettings
	otherPolicies []hcn.EndpointPolicy
}

func newStaleChains() *staleChains {
	return &staleChains{}
}

func (pMgr *PolicyManager) bootup(epIDs []string) error {
	var aggregateErr error
	for _, epID := range epIDs {
		err := pMgr.removePolicyByEndpointID("", epID, 0, resetAllACLs)
		if err != nil {
			aggregateErr = fmt.Errorf("[PolicyManagerWindows] Skipping removing policies on %s ID Endpoint with %s err\n Previous %w", epID, err.Error(), aggregateErr)
			continue
		}
	}
	return aggregateErr
}

func (pMgr *PolicyManager) reconcile() {
	// not implemented
}

// addPolicy will add the policy for each specified endpoint if the policy doesn't exist on the endpoint yet,
// and will add the endpoint to the PodEndpoints of the policy if successful.
func (pMgr *PolicyManager) addPolicy(policy *NPMNetworkPolicy, endpointList map[string]string) error {
	if len(endpointList) == 0 {
		klog.Infof("[PolicyManagerWindows] No Endpoints to apply policy %s on", policy.PolicyKey)
		return nil
	}
	klog.Infof("[PolicyManagerWindows] adding policy %s on %+v", policy.PolicyKey, endpointList)

	// 1. remove stale endpoints from policy.PodEndpoints and skip adding to endpoints that already have the policy
	if policy.PodEndpoints == nil {
		policy.PodEndpoints = make(map[string]string)
	}

	for epIP, epID := range policy.PodEndpoints {
		oldEPID, ok := endpointList[epIP]
		if !ok {
			continue
		}

		if oldEPID != epID {
			// If the expected ID is not same as epID, there is a chance that old pod got deleted
			// and same IP is used by new pod with new endpoint.
			// so we should delete the non-existent endpoint from policy reference
			klog.Infof("[PolicyManagerWindows] removing endpoint from policy's current endpoints since the endpoint ID has changed. policy: %s, endpoint IP: %s, new ID: %s, previous ID: %s", policy.PolicyKey, epIP, epID, oldEPID)
			delete(policy.PodEndpoints, epIP)
			continue
		}

		klog.Infof("[PolicyManagerWindows] will not add policy %s to endpoint since it already exists there. endpoint IP: %s, endpoint ID: %s", policy.PolicyKey, epIP, epID)
		// Deleting the endpoint from EPList so that the policy is not added to this endpoint again
		delete(endpointList, epIP)
	}

	if len(endpointList) == 0 {
		klog.Infof("[PolicyManagerWindows] After checking policy's current endpoints, no endpoints to apply policy %s on", policy.PolicyKey)
		return nil
	}

	// 2. apply the policy to all the endpoints via HNS
	rulesToAdd, err := getSettingsFromACL(policy)
	if err != nil {
		return err
	}
	epPolicyRequest, err := getEPPolicyReqFromACLSettings(rulesToAdd)
	if err != nil {
		return err
	}

	var aggregateErr error
	for epIP, epID := range endpointList {
		err = pMgr.applyPoliciesToEndpointID(epID, epPolicyRequest)
		if err != nil {
			klog.Infof("[PolicyManagerWindows] Failed to add policy on %s ID Endpoint with %s err", epID, err.Error())
			// Do not return if one endpoint fails, try all endpoints.
			// aggregate the error message and return it at the end
			aggregateErr = fmt.Errorf("Failed to add policy on %s ID Endpoint with %s err \n Previous %w", epID, err.Error(), aggregateErr)
			continue
		}
		// Now update policy cache to reflect new endpoint
		policy.PodEndpoints[epIP] = epID
	}

	return aggregateErr
}

// removePolicy will remove the policy from the specified endpoints, or
// if the endpointList is nil, then the policy will be removed from the PodEndpoints of the policy
func (pMgr *PolicyManager) removePolicy(policy *NPMNetworkPolicy, endpointList map[string]string) error {
	if endpointList == nil {
		if len(policy.PodEndpoints) == 0 {
			klog.Infof("[PolicyManagerWindows] No Endpoints to remove policy %s on", policy.PolicyKey)
			return nil
		}
		endpointList = policy.PodEndpoints
	}

	rulesToRemove, err := getSettingsFromACL(policy)
	if err != nil {
		return err
	}
	klog.Infof("[PolicyManagerWindows] To Remove Policy: %s \n To Delete ACLs: %+v \n To Remove From %+v endpoints", policy.PolicyKey, rulesToRemove, endpointList)
	// If remove bug is solved we can directly remove the exact policy from the endpoint
	// but if the bug is not solved then get all existing policies and remove relevant policies from list
	// then apply remaining policies onto the endpoint
	var aggregateErr error
	numOfRulesToRemove := len(rulesToRemove)
	for epIPAddr, epID := range endpointList {
		err := pMgr.removePolicyByEndpointID(rulesToRemove[0].Id, epID, numOfRulesToRemove, removeOnlyGivenPolicy)
		if err != nil {
			aggregateErr = fmt.Errorf("[PolicyManagerWindows] Skipping removing policies on %s ID Endpoint with %s err\n Previous %w", epID, err.Error(), aggregateErr)
			continue
		}

		// Delete podendpoint from policy cache
		delete(policy.PodEndpoints, epIPAddr)
	}

	return aggregateErr
}

func (pMgr *PolicyManager) removePolicyByEndpointID(ruleID, epID string, noOfRulesToRemove int, resetAllACL shouldResetAllACLs) error {
	epObj, err := pMgr.getEndpointByID(epID)
	if err != nil {
		return fmt.Errorf("[PolicyManagerWindows] Skipping removing policies on %s ID Endpoint with %s err", epID, err.Error())
	}
	if len(epObj.Policies) == 0 {
		klog.Infof("[DataPlanewindows] No Policies to remove on %s ID Endpoint", epID)
	}

	epBuilder, err := splitEndpointPolicies(epObj.Policies)
	if err != nil {
		return fmt.Errorf("[PolicyManagerWindows] Skipping removing policies on %s ID Endpoint with %s err", epID, err.Error())
	}

	if resetAllACL {
		klog.Infof("[PolicyManagerWindows] Resetting all ACL Policies on %s ID Endpoint", epID)
		if !epBuilder.resetAllNPMAclPolicies() {
			klog.Infof("[PolicyManagerWindows] No Azure-NPM ACL Policies on %s ID Endpoint to reset", epID)
			return nil
		}
	} else {
		klog.Infof("[PolicyManagerWindows] Resetting only ACL Policies with %s ID on %s ID Endpoint", ruleID, epID)
		if !epBuilder.compareAndRemovePolicies(ruleID, noOfRulesToRemove) {
			klog.Infof("[PolicyManagerWindows] No Policies with ID %s on %s ID Endpoint", ruleID, epID)
			return nil
		}
	}
	klog.Infof("[DataPlanewindows] Epbuilder ACL policies before removing %+v", epBuilder.aclPolicies)
	klog.Infof("[DataPlanewindows] Epbuilder Other policies before removing %+v", epBuilder.otherPolicies)
	epPolicies, err := epBuilder.getHCNPolicyRequest()
	if err != nil {
		return fmt.Errorf("[DataPlanewindows] Skipping removing policies on %s ID Endpoint with %s err", epID, err.Error())
	}

	err = pMgr.updatePoliciesOnEndpoint(epObj, epPolicies)
	if err != nil {
		return fmt.Errorf("[DataPlanewindows] Skipping removing policies on %s ID Endpoint with %s err", epID, err.Error())
	}
	return nil
}

// addEPPolicyWithEpID given an EP ID and a list of policies, add the policies to the endpoint
func (pMgr *PolicyManager) applyPoliciesToEndpointID(epID string, policies hcn.PolicyEndpointRequest) error {
	epObj, err := pMgr.getEndpointByID(epID)
	if err != nil {
		klog.Infof("[PolicyManagerWindows] Skipping applying policies %s ID Endpoint with %s err", epID, err.Error())
		return err
	}

	err = pMgr.ioShim.Hns.ApplyEndpointPolicy(epObj, hcn.RequestTypeAdd, policies)
	if err != nil {
		klog.Infof("[PolicyManagerWindows]Failed to apply policies on %s ID Endpoint with %s err", epID, err.Error())
		return err
	}
	return nil
}

// addEPPolicyWithEpID given an EP ID and a list of policies, add the policies to the endpoint
func (pMgr *PolicyManager) updatePoliciesOnEndpoint(epObj *hcn.HostComputeEndpoint, policies hcn.PolicyEndpointRequest) error {
	err := pMgr.ioShim.Hns.ApplyEndpointPolicy(epObj, hcn.RequestTypeUpdate, policies)
	if err != nil {
		klog.Infof("[PolicyManagerWindows]Failed to update/remove policies on %s ID Endpoint with %s err", epObj.Id, err.Error())
		return err
	}
	return nil
}

func (pMgr *PolicyManager) getEndpointByID(id string) (*hcn.HostComputeEndpoint, error) {
	epObj, err := pMgr.ioShim.Hns.GetEndpointByID(id)
	if err != nil {
		klog.Infof("[PolicyManagerWindows] Failed to get EndPoint object of %s ID from HNS", id)
		return nil, err
	}
	return epObj, nil
}

// getEPPolicyReqFromACLSettings converts given ACLSettings into PolicyEndpointRequest
func getEPPolicyReqFromACLSettings(settings []*NPMACLPolSettings) (hcn.PolicyEndpointRequest, error) {
	policyToAdd := hcn.PolicyEndpointRequest{
		Policies: make([]hcn.EndpointPolicy, len(settings)),
	}

	for i, acl := range settings {
		klog.Infof("Acl settings: %+v", acl)
		byteACL, err := json.Marshal(acl)
		if err != nil {
			klog.Infof("[PolicyManagerWindows] Failed to marshall ACL settings %+v", acl)
			return hcn.PolicyEndpointRequest{}, ErrFailedMarshalACLSettings
		}

		epPolicy := hcn.EndpointPolicy{
			Type:     hcn.ACL,
			Settings: byteACL,
		}
		policyToAdd.Policies[i] = epPolicy
	}
	return policyToAdd, nil
}

func getSettingsFromACL(policy *NPMNetworkPolicy) ([]*NPMACLPolSettings, error) {
	hnsRules := make([]*NPMACLPolSettings, len(policy.ACLs))
	for i, acl := range policy.ACLs {
		rule, err := acl.convertToAclSettings(policy.ACLPolicyID)
		if err != nil {
			// TODO need some retry mechanism to check why the translations failed
			return hnsRules, err
		}
		hnsRules[i] = rule
	}
	return hnsRules, nil
}

// splitEndpointPolicies this function takes in endpoint policies and separated ACL policies from other policies
func splitEndpointPolicies(endpointPolicies []hcn.EndpointPolicy) (*endpointPolicyBuilder, error) {
	epBuilder := newEndpointPolicyBuilder()
	for _, policy := range endpointPolicies {
		if policy.Type == hcn.ACL {
			var aclSettings *NPMACLPolSettings
			err := json.Unmarshal(policy.Settings, &aclSettings)
			if err != nil {
				return nil, ErrFailedUnMarshalACLSettings
			}
			epBuilder.aclPolicies = append(epBuilder.aclPolicies, aclSettings)
		} else {
			epBuilder.otherPolicies = append(epBuilder.otherPolicies, policy)
		}
	}
	return epBuilder, nil
}

func newEndpointPolicyBuilder() *endpointPolicyBuilder {
	return &endpointPolicyBuilder{
		aclPolicies:   []*NPMACLPolSettings{},
		otherPolicies: []hcn.EndpointPolicy{},
	}
}

func (epBuilder *endpointPolicyBuilder) getHCNPolicyRequest() (hcn.PolicyEndpointRequest, error) {
	epPolReq, err := getEPPolicyReqFromACLSettings(epBuilder.aclPolicies)
	if err != nil {
		return hcn.PolicyEndpointRequest{}, err
	}

	// Make sure other policies are applied first
	epPolReq.Policies = append(epBuilder.otherPolicies, epPolReq.Policies...)
	return epPolReq, nil
}

func (epBuilder *endpointPolicyBuilder) compareAndRemovePolicies(ruleIDToRemove string, lenOfRulesToRemove int) bool {
	// All ACl policies in a given Netpol will have the same ID
	// starting with "azure-acl-" prefix
	aclFound := false
	toDeleteIndexes := map[int]struct{}{}
	for i, acl := range epBuilder.aclPolicies {
		// First check if ID is present and equal, this saves compute cycles to compare both objects
		if ruleIDToRemove == acl.Id {
			// Remove the ACL policy from the list
			klog.Infof("[PolicyManagerWindows] Found ACL with ID %s and removing it", acl.Id)
			toDeleteIndexes[i] = struct{}{}
			lenOfRulesToRemove--
			aclFound = true
		}
	}
	// If ACl Policies are not found, it means that we might have removed them earlier
	// or never applied them
	if !aclFound {
		klog.Infof("[PolicyManagerWindows] ACL with ID %s is not Found in Dataplane", ruleIDToRemove)
		return aclFound
	}
	epBuilder.removeACLPolicyAtIndex(toDeleteIndexes)
	// if there are still rules to remove, it means that we might have not added all the policies in the add
	// case and were only able to find a portion of the rules to remove
	if lenOfRulesToRemove > 0 {
		klog.Infof("[PolicyManagerWindows] did not find %d no of ACLs to remove", lenOfRulesToRemove)
	}
	return aclFound
}

func (epBuilder *endpointPolicyBuilder) resetAllNPMAclPolicies() bool {
	if len(epBuilder.aclPolicies) == 0 {
		return false
	}
	aclFound := false
	toDeleteIndexes := map[int]struct{}{}
	for i, acl := range epBuilder.aclPolicies {
		// First check if ID is present and equal, this saves compute cycles to compare both objects
		if strings.HasPrefix(acl.Id, policyIDPrefix) {
			// Remove the ACL policy from the list
			klog.Infof("[PolicyManagerWindows] Found ACL with ID %s and removing it", acl.Id)
			toDeleteIndexes[i] = struct{}{}
			aclFound = true
		}
	}
	if len(toDeleteIndexes) == len(epBuilder.aclPolicies) {
		epBuilder.aclPolicies = []*NPMACLPolSettings{}
		return aclFound
	}
	epBuilder.removeACLPolicyAtIndex(toDeleteIndexes)
	return aclFound
}

func (epBuilder *endpointPolicyBuilder) removeACLPolicyAtIndex(indexes map[int]struct{}) {
	if len(indexes) == 0 {
		return
	}
	tempAclPolicies := []*NPMACLPolSettings{}
	for i, acl := range epBuilder.aclPolicies {
		if _, ok := indexes[i]; !ok {
			tempAclPolicies = append(tempAclPolicies, acl)
		}
	}
	epBuilder.aclPolicies = tempAclPolicies
}
