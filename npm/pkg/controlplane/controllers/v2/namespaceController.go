// Copyright 2018 Microsoft. All rights reserved.
// MIT License
package controllers

import (
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/Azure/azure-container-networking/npm/metrics"
	"github.com/Azure/azure-container-networking/npm/pkg/controlplane/controllers/common"
	"github.com/Azure/azure-container-networking/npm/pkg/dataplane"
	"github.com/Azure/azure-container-networking/npm/pkg/dataplane/ipsets"
	"github.com/Azure/azure-container-networking/npm/util"
	corev1 "k8s.io/api/core/v1"
	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	k8slabels "k8s.io/apimachinery/pkg/labels"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/apimachinery/pkg/util/wait"
	coreinformer "k8s.io/client-go/informers/core/v1"
	corelisters "k8s.io/client-go/listers/core/v1"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/util/workqueue"
	"k8s.io/klog"
)

type LabelAppendOperation bool

const (
	clearExistingLabels    LabelAppendOperation = true
	appendToExistingLabels LabelAppendOperation = false
)

var errWorkqueueFormatting = errors.New("error in formatting")

// NpmNamespaceCache to store namespace struct in nameSpaceController.go.
// Since this cache is shared between podController and NamespaceController,
// it has mutex for avoiding racing condition between them.
type NpmNamespaceCache struct {
	sync.RWMutex
	NsMap map[string]*common.Namespace // Key is ns-<nsname>
}

func (c *NpmNamespaceCache) GetCache() map[string]*common.Namespace {
	c.RLock()
	defer c.RUnlock()
	return c.NsMap
}

func (n *NpmNamespaceCache) MarshalJSON() ([]byte, error) {
	n.RLock()
	defer n.RUnlock()

	nsMapRaw, err := json.Marshal(n.NsMap)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal nsMap due to %w", err)
	}

	return nsMapRaw, nil
}

type NamespaceController struct {
	dp                dataplane.GenericDataplane
	nameSpaceLister   corelisters.NamespaceLister
	workqueue         workqueue.RateLimitingInterface
	npmNamespaceCache *NpmNamespaceCache
}

func NewNamespaceController(nameSpaceInformer coreinformer.NamespaceInformer, dp dataplane.GenericDataplane, npmNamespaceCache *NpmNamespaceCache) *NamespaceController {
	nameSpaceController := &NamespaceController{
		dp:                dp,
		nameSpaceLister:   nameSpaceInformer.Lister(),
		workqueue:         workqueue.NewNamedRateLimitingQueue(workqueue.DefaultControllerRateLimiter(), "Namespaces"),
		npmNamespaceCache: npmNamespaceCache,
	}

	nameSpaceInformer.Informer().AddEventHandler(
		cache.ResourceEventHandlerFuncs{
			AddFunc:    nameSpaceController.addNamespace,
			UpdateFunc: nameSpaceController.updateNamespace,
			DeleteFunc: nameSpaceController.deleteNamespace,
		},
	)
	return nameSpaceController
}

func (n *NamespaceController) GetCache() map[string]*common.Namespace {
	return n.npmNamespaceCache.GetCache()
}

// filter this event if we do not need to handle this event
func (nsc *NamespaceController) needSync(obj interface{}, event string) (string, bool) {
	needSync := false
	var key string

	nsObj, ok := obj.(*corev1.Namespace)
	if !ok {
		metrics.SendErrorLogAndMetric(util.NSID, "[NAMESPACE %s EVENT] Received unexpected object type: %v", event, obj)
		return key, needSync
	}

	var err error
	if key, err = cache.MetaNamespaceKeyFunc(obj); err != nil {
		utilruntime.HandleError(err)
		metrics.SendErrorLogAndMetric(util.NSID, "[NAMESPACE %s EVENT] Error: NamespaceKey is empty for %s namespace", event, nsObj.Name)
		return key, needSync
	}

	needSync = true
	return key, needSync
}

func (nsc *NamespaceController) addNamespace(obj interface{}) {
	key, needSync := nsc.needSync(obj, "ADD")
	if !needSync {
		return
	}
	nsc.workqueue.Add(key)
}

func (nsc *NamespaceController) updateNamespace(old, newns interface{}) {
	key, needSync := nsc.needSync(newns, "UPDATE")
	if !needSync {
		return
	}

	nsObj, _ := newns.(*corev1.Namespace)
	oldNsObj, ok := old.(*corev1.Namespace)
	if ok {
		if oldNsObj.ResourceVersion == nsObj.ResourceVersion {
			return
		}
	}

	nsc.workqueue.Add(key)
}

func (nsc *NamespaceController) deleteNamespace(obj interface{}) {
	nsObj, ok := obj.(*corev1.Namespace)
	// DeleteFunc gets the final state of the resource (if it is known).
	// Otherwise, it gets an object of type DeletedFinalStateUnknown.
	// This can happen if the watch is closed and misses the delete event and
	// the controller doesn't notice the deletion until the subsequent re-list
	if !ok {
		tombstone, ok := obj.(cache.DeletedFinalStateUnknown)
		if !ok {
			metrics.SendErrorLogAndMetric(util.NSID, "[NAMESPACE DELETE EVENT]: Received unexpected object type: %v", obj)
			return
		}

		if nsObj, ok = tombstone.Obj.(*corev1.Namespace); !ok {
			metrics.SendErrorLogAndMetric(util.NSID, "[NAMESPACE DELETE EVENT]: Received unexpected object type (error decoding object tombstone, invalid type): %v", obj)
			return
		}
	}

	var err error
	var key string
	if key, err = cache.MetaNamespaceKeyFunc(nsObj); err != nil {
		utilruntime.HandleError(err)
		metrics.SendErrorLogAndMetric(util.NSID, "[NAMESPACE DELETE EVENT] Error: nameSpaceKey is empty for %s namespace", nsObj.Name)
		return
	}

	nsc.workqueue.Add(key)
}

func (nsc *NamespaceController) Run(stopCh <-chan struct{}) {
	defer utilruntime.HandleCrash()
	defer nsc.workqueue.ShutDown()

	klog.Info("Starting Namespace controller\n")
	klog.Info("Starting workers")
	// Launch workers to process namespace resources
	go wait.Until(nsc.runWorker, time.Second, stopCh)

	klog.Info("Started workers")
	<-stopCh
	klog.Info("Shutting down workers")
}

func (nsc *NamespaceController) runWorker() {
	for nsc.processNextWorkItem() {
	}
}

func (nsc *NamespaceController) processNextWorkItem() bool {
	obj, shutdown := nsc.workqueue.Get()

	if shutdown {
		return false
	}

	err := func(obj interface{}) error {
		defer nsc.workqueue.Done(obj)
		var key string
		var ok bool
		if key, ok = obj.(string); !ok {
			// As the item in the workqueue is actually invalid, we call
			// Forget here else we'd go into a loop of attempting to
			// process a work item that is invalid.
			nsc.workqueue.Forget(obj)
			utilruntime.HandleError(fmt.Errorf("expected string in workqueue but got %#v, err %w", obj, errWorkqueueFormatting))
			return nil
		}
		// Run the syncNamespace, passing it the namespace string of the
		// resource to be synced.
		if err := nsc.syncNamespace(key); err != nil {
			// Put the item back on the workqueue to handle any transient errors.
			nsc.workqueue.AddRateLimited(key)
			metrics.SendErrorLogAndMetric(util.NSID, "[processNextWorkItem] Error: failed to syncNamespace %s. Requeuing with err: %v", key, err)
			return err
		}
		// Finally, if no error occurs we Forget this item so it does not
		// get queued again until another change happens.
		nsc.workqueue.Forget(obj)
		klog.Infof("Successfully synced '%s'", key)
		return nil
	}(obj)
	if err != nil {
		utilruntime.HandleError(err)
		return true
	}

	return true
}

// syncNamespace compares the actual state with the desired, and attempts to converge the two.
func (nsc *NamespaceController) syncNamespace(nsKey string) error {
	// timer for recording execution times
	timer := metrics.StartNewTimer()

	// Get the Namespace resource with this key
	nsObj, err := nsc.nameSpaceLister.Get(nsKey)

	// apply dataplane and record exec time after syncing
	operationKind := metrics.NoOp
	defer func() {
		dperr := nsc.dp.ApplyDataPlane()

		// NOTE: it may seem like Prometheus is considering some ns create events as updates.
		// This happens when pod create events beat ns create events, so the pod controller will create the ipset
		// for the ns. This results in a ns "update" later when the ns controller processes the ns create event

		// can't record this in another deferred func since deferred funcs are processed in LIFO order
		metrics.RecordControllerNamespaceExecTime(timer, operationKind, err != nil && dperr != nil)

		if dperr != nil {
			err = fmt.Errorf("failed with error %w, apply failed with %v", err, dperr)
		}
	}()

	// hold lock to avoid racing condition with PodController
	nsc.npmNamespaceCache.Lock()
	defer nsc.npmNamespaceCache.Unlock()
	if err != nil {
		if k8serrors.IsNotFound(err) {
			klog.Infof("Namespace %s not found, may be it is deleted", nsKey)

			if _, ok := nsc.npmNamespaceCache.NsMap[nsKey]; ok {
				// record time to delete namespace if it exists (can't call within cleanDeletedNamespace because this can be called by a pod update)
				operationKind = metrics.DeleteOp
			}

			// cleanDeletedNamespace will check if the NS exists in cache, if it does, then proceeds with deletion
			// if it does not exists, then event will be no-op
			err = nsc.cleanDeletedNamespace(nsKey)
			if err != nil {
				// need to retry this cleaning-up process
				metrics.SendErrorLogAndMetric(util.NSID, "Error: %v when namespace is not found", err)
				return fmt.Errorf("Error: %w when namespace is not found", err)
			}
		}
		return err
	}

	if nsObj.DeletionTimestamp != nil || nsObj.DeletionGracePeriodSeconds != nil {
		if _, ok := nsc.npmNamespaceCache.NsMap[nsKey]; ok {
			// record time to delete namespace if it exists (can't call within cleanDeletedNamespace because this can be called by a pod update)
			operationKind = metrics.DeleteOp
		}
		return nsc.cleanDeletedNamespace(nsKey)
	}

	cachedNsObj, nsExists := nsc.npmNamespaceCache.NsMap[nsKey]
	if nsExists {
		if k8slabels.Equals(cachedNsObj.LabelsMap, nsObj.ObjectMeta.Labels) {
			klog.Infof("[NAMESPACE UPDATE EVENT] Namespace [%s] labels did not change", nsKey)
			return nil
		}
	}

	operationKind, err = nsc.syncUpdateNamespace(nsObj)
	if err != nil {
		metrics.SendErrorLogAndMetric(util.NSID, "[syncNamespace] failed to sync namespace due to  %s", err.Error())
		return err
	}

	return nil
}

// syncAddNamespace handles adding namespace to ipset.
func (nsc *NamespaceController) syncAddNamespace(nsObj *corev1.Namespace) error {
	namespaceSets := []*ipsets.IPSetMetadata{ipsets.NewIPSetMetadata(nsObj.ObjectMeta.Name, ipsets.Namespace)}
	setsToAddNamespaceTo := []*ipsets.IPSetMetadata{kubeAllNamespaces}

	npmNs := common.NewNs(nsObj.ObjectMeta.Name)
	nsc.npmNamespaceCache.NsMap[nsObj.ObjectMeta.Name] = npmNs

	// Add the namespace to its label's ipset list.
	for nsLabelKey, nsLabelVal := range nsObj.ObjectMeta.Labels {
		nsLabelKeyValue := util.GetIpSetFromLabelKV(nsLabelKey, nsLabelVal)
		klog.Infof("Adding namespace %s to ipset list %s and %s", nsObj.ObjectMeta.Name, nsLabelKey, nsLabelKeyValue)
		labelIPSets := []*ipsets.IPSetMetadata{
			ipsets.NewIPSetMetadata(nsLabelKey, ipsets.KeyLabelOfNamespace),
			ipsets.NewIPSetMetadata(nsLabelKeyValue, ipsets.KeyValueLabelOfNamespace),
		}

		setsToAddNamespaceTo = append(setsToAddNamespaceTo, labelIPSets...)

		// Append succeeded labels to the cache NS obj
		npmNs.AppendLabels(map[string]string{nsLabelKey: nsLabelVal}, common.AppendToExistingLabels)
	}

	if err := nsc.dp.AddToLists(setsToAddNamespaceTo, namespaceSets); err != nil {
		return fmt.Errorf("failed to sync add namespace with error %w", err)
	}

	return nil
}

// syncUpdateNamespace handles updating namespace in ipset.
func (nsc *NamespaceController) syncUpdateNamespace(newNsObj *corev1.Namespace) (metrics.OperationKind, error) {
	var err error
	newNsName, newNsLabel := newNsObj.ObjectMeta.Name, newNsObj.ObjectMeta.Labels
	klog.Infof("NAMESPACE UPDATING:\n namespace: [%s/%v]", newNsName, newNsLabel)

	// If previous syncAddNamespace failed for some reasons
	// before caching npm namespace object or syncUpdateNamespace is called due to namespace creation event,
	// then there is no cached object in nsMap.
	curNsObj, exists := nsc.npmNamespaceCache.NsMap[newNsName]
	if !exists {
		if newNsObj.ObjectMeta.DeletionTimestamp == nil && newNsObj.ObjectMeta.DeletionGracePeriodSeconds == nil {
			if er := nsc.syncAddNamespace(newNsObj); er != nil {
				return metrics.CreateOp, fmt.Errorf("failed to sync add namespace with err %w", err)
			}
		}

		return metrics.CreateOp, nil
	}
	// now we know this is an update event, and we'll return metrics.UpdateOp

	// If the Namespace is not deleted, delete removed labels and create new labels
	addToIPSets, deleteFromIPSets := util.GetIPSetListCompareLabels(curNsObj.LabelsMap, newNsLabel)
	// Delete the namespace from its label's ipset list.
	for _, nsLabelVal := range deleteFromIPSets {
		var labelSet *ipsets.IPSetMetadata
		if util.IsKeyValueLabelSetName(nsLabelVal) {
			labelSet = ipsets.NewIPSetMetadata(nsLabelVal, ipsets.KeyValueLabelOfNamespace)
		} else {
			labelSet = ipsets.NewIPSetMetadata(nsLabelVal, ipsets.KeyLabelOfNamespace)
		}
		toBeRemoved := []*ipsets.IPSetMetadata{ipsets.NewIPSetMetadata(newNsName, ipsets.Namespace)}

		klog.Infof("Deleting namespace %s from ipset list %s", newNsName, nsLabelVal)
		if err = nsc.dp.RemoveFromList(labelSet, toBeRemoved); err != nil {
			metrics.SendErrorLogAndMetric(util.NSID, "[UpdateNamespace] Error: failed to delete namespace %s from ipset list %s with err: %v", newNsName, nsLabelVal, err)
			return metrics.UpdateOp, fmt.Errorf("failed to remove from list during sync update namespace with err %w", err)
		}
		// {IMPORTANT} The order of compared list will be key and then key+val. NPM should only append after both key
		// key + val ipsets are worked on.
		// (TODO) need to remove this ordering dependency
		removedLabelKey, removedLabelValue := util.GetLabelKVFromSet(nsLabelVal)
		if removedLabelValue != "" {
			curNsObj.RemoveLabelsWithKey(removedLabelKey)
		}
	}

	// Add the namespace to its label's ipset list.
	for _, nsLabelVal := range addToIPSets {
		klog.Infof("Adding namespace %s to ipset list %s", newNsName, nsLabelVal)

		var labelSet []*ipsets.IPSetMetadata
		if util.IsKeyValueLabelSetName(nsLabelVal) {
			labelSet = []*ipsets.IPSetMetadata{ipsets.NewIPSetMetadata(nsLabelVal, ipsets.KeyValueLabelOfNamespace)}
		} else {
			labelSet = []*ipsets.IPSetMetadata{ipsets.NewIPSetMetadata(nsLabelVal, ipsets.KeyLabelOfNamespace)}
		}
		toBeAdded := []*ipsets.IPSetMetadata{ipsets.NewIPSetMetadata(newNsName, ipsets.Namespace)}

		if err = nsc.dp.AddToLists(labelSet, toBeAdded); err != nil {
			metrics.SendErrorLogAndMetric(util.NSID, "[UpdateNamespace] Error: failed to add namespace %s to ipset list %s with err: %v", newNsName, nsLabelVal, err)
			return metrics.UpdateOp, fmt.Errorf("failed to add %v sets to %v lists during addtolists in sync update namespace with err %w", toBeAdded, labelSet, err)
		}
		// {IMPORTANT} Same as above order is assumed to be key and then key+val. NPM should only append to existing labels
		// only after both ipsets for a given label's key value pair are added successfully
		addedLabelKey, addedLabelValue := util.GetLabelKVFromSet(nsLabelVal)
		if addedLabelValue != "" {
			curNsObj.AppendLabels(map[string]string{addedLabelKey: addedLabelValue}, common.AppendToExistingLabels)
		}
	}

	// Append all labels to the cache NS obj
	// If due to ordering issue the above deleted and added labels are not correct,
	// this below appendLabels will help ensure correct state in cache for all successful ops.
	curNsObj.AppendLabels(newNsLabel, common.ClearExistingLabels)
	nsc.npmNamespaceCache.NsMap[newNsName] = curNsObj

	return metrics.UpdateOp, nil
}

// cleanDeletedNamespace handles deleting namespace from ipset.
func (nsc *NamespaceController) cleanDeletedNamespace(cachedNsKey string) error {
	klog.Infof("NAMESPACE DELETING: [%s]", cachedNsKey)
	cachedNsObj, exists := nsc.npmNamespaceCache.NsMap[cachedNsKey]
	if !exists {
		return nil
	}

	klog.Infof("NAMESPACE DELETING cached labels: [%s/%v]", cachedNsKey, cachedNsObj.LabelsMap)

	var err error
	toBeDeletedNs := []*ipsets.IPSetMetadata{ipsets.NewIPSetMetadata(cachedNsKey, ipsets.Namespace)}
	// Delete the namespace from its label's ipset list.
	for nsLabelKey, nsLabelVal := range cachedNsObj.LabelsMap {

		labelKey := ipsets.NewIPSetMetadata(nsLabelKey, ipsets.KeyLabelOfNamespace)
		klog.Infof("Deleting namespace %s from ipset list %s", cachedNsKey, labelKey)
		if err = nsc.dp.RemoveFromList(labelKey, toBeDeletedNs); err != nil {
			metrics.SendErrorLogAndMetric(util.NSID, "[DeleteNamespace] Error: failed to delete namespace %s from ipset list %s with err: %v", cachedNsKey, labelKey, err)
			return fmt.Errorf("failed to clean deleted namespace when deleting key with err %w", err)
		}

		labelIpsetName := util.GetIpSetFromLabelKV(nsLabelKey, nsLabelVal)
		labelKeyValue := ipsets.NewIPSetMetadata(labelIpsetName, ipsets.KeyValueLabelOfNamespace)
		klog.Infof("Deleting namespace %s from ipset list %s", cachedNsKey, labelIpsetName)
		if err = nsc.dp.RemoveFromList(labelKeyValue, toBeDeletedNs); err != nil {
			metrics.SendErrorLogAndMetric(util.NSID, "[DeleteNamespace] Error: failed to delete namespace %s from ipset list %s with err: %v", cachedNsKey, labelIpsetName, err)
			return fmt.Errorf("failed to clean deleted namespace when deleting key value with err %w", err)
		}

		// remove labels from the cache NS obj
		cachedNsObj.RemoveLabelsWithKey(nsLabelKey)
	}

	allNamespacesSet := ipsets.NewIPSetMetadata(util.KubeAllNamespacesFlag, ipsets.KeyLabelOfNamespace)
	toBeDeletedCachedKey := []*ipsets.IPSetMetadata{ipsets.NewIPSetMetadata(cachedNsKey, ipsets.Namespace)}

	// Delete the namespace from all-namespace ipset list.
	if err = nsc.dp.RemoveFromList(allNamespacesSet, toBeDeletedCachedKey); err != nil {
		metrics.SendErrorLogAndMetric(util.NSID, "[DeleteNamespace] Error: failed to delete namespace %s from ipset list %s with err: %v", cachedNsKey, util.KubeAllNamespacesFlag, err)
		return fmt.Errorf("failed to remove from list during clean deleted namespace %w", err)
	}

	delete(nsc.npmNamespaceCache.NsMap, cachedNsKey)

	return nil
}
