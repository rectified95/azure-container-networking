// Copyright 2018 Microsoft. All rights reserved.
// MIT License
package controllers

import (
	"encoding/json"
	"fmt"
	"reflect"
	"sync"
	"time"

	"github.com/Azure/azure-container-networking/npm/metrics"
	"github.com/Azure/azure-container-networking/npm/util"
	ebpf "github.com/Azure/azure-container-networking/test/ebpf"
	npmerrors "github.com/Azure/azure-container-networking/npm/util/errors"
	"github.com/pkg/errors"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	k8slabels "k8s.io/apimachinery/pkg/labels"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/apimachinery/pkg/util/wait"
	coreinformer "k8s.io/client-go/informers/core/v1"
	corelisters "k8s.io/client-go/listers/core/v1"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/util/workqueue"
	"k8s.io/klog"
)

// NamedPortOperation decides opeartion (e.g., delete or add) for named port ipset in manageNamedPortIpsets
type NamedPortOperation string

const (
	deleteNamedPort NamedPortOperation = "del"
	addNamedPort    NamedPortOperation = "add"
)


type NpmPod struct {
	Name           string
	Namespace      string
	PodIP          string
	Labels         map[string]string
	ContainerPorts []corev1.ContainerPort
	Phase          corev1.PodPhase
}

func newNpmPod(podObj *corev1.Pod) *NpmPod {
	return &NpmPod{
		Name:           podObj.ObjectMeta.Name,
		Namespace:      podObj.ObjectMeta.Namespace,
		PodIP:          podObj.Status.PodIP,
		Labels:         make(map[string]string),
		ContainerPorts: []corev1.ContainerPort{},
		Phase:          podObj.Status.Phase,
	}
}

func (nPod *NpmPod) appendLabels(newLabelMap map[string]string, clear LabelAppendOperation) {
	if clear {
		nPod.Labels = make(map[string]string)
	}
	for k, v := range newLabelMap {
		nPod.Labels[k] = v
	}
}

func (nPod *NpmPod) removeLabelsWithKey(key string) {
	delete(nPod.Labels, key)
}

func (nPod *NpmPod) appendContainerPorts(podObj *corev1.Pod) {
	nPod.ContainerPorts = getContainerPortList(podObj)
}

func (nPod *NpmPod) removeContainerPorts() {
	nPod.ContainerPorts = []corev1.ContainerPort{}
}

// This function can be expanded to other attribs if needed
func (nPod *NpmPod) updateNpmPodAttributes(podObj *corev1.Pod) {
	if nPod.Phase != podObj.Status.Phase {
		nPod.Phase = podObj.Status.Phase
	}
}

// noUpdate evaluates whether NpmPod is required to be update given podObj.
func (nPod *NpmPod) noUpdate(podObj *corev1.Pod) bool {
	return nPod.Namespace == podObj.ObjectMeta.Namespace &&
		nPod.Name == podObj.ObjectMeta.Name &&
		nPod.Phase == podObj.Status.Phase &&
		nPod.PodIP == podObj.Status.PodIP &&
		k8slabels.Equals(nPod.Labels, podObj.ObjectMeta.Labels) &&
		// TODO(jungukcho) to avoid using DeepEqual for ContainerPorts,
		// it needs a precise sorting. Will optimize it later if needed.
		reflect.DeepEqual(nPod.ContainerPorts, getContainerPortList(podObj))
}

type PodController struct {
	podLister corelisters.PodLister
	workqueue workqueue.RateLimitingInterface
	dp *ebpf.EBPF_DP
	podMap    map[string]*NpmPod // Key is <nsname>/<podname>
	sync.Mutex
	npmNamespaceCache *NpmNamespaceCache
}

func NewPodController(podInformer coreinformer.PodInformer, dp *ebpf.EBPF_DP, npmNamespaceCache *NpmNamespaceCache) *PodController {
	podController := &PodController{
		podLister:         podInformer.Lister(),
		workqueue:         workqueue.NewNamedRateLimitingQueue(workqueue.DefaultControllerRateLimiter(), "Pods"),
		dp:                dp,
		podMap:            make(map[string]*NpmPod),
		npmNamespaceCache: npmNamespaceCache,
	}

	podInformer.Informer().AddEventHandler(
		cache.ResourceEventHandlerFuncs{
			AddFunc:    podController.addPod,
			UpdateFunc: podController.updatePod,
			DeleteFunc: podController.deletePod,
		},
	)
	return podController
}

func (c *PodController) MarshalJSON() ([]byte, error) {
	c.Lock()
	defer c.Unlock()

	podMapRaw, err := json.Marshal(c.podMap)
	if err != nil {
		return nil, errors.Errorf("failed to marshal podMap due to %v", err)
	}

	return podMapRaw, nil
}

func (c *PodController) LengthOfPodMap() int {
	return len(c.podMap)
}

// needSync filters the event if the event is not required to handle
func (c *PodController) needSync(eventType string, obj interface{}) (string, bool) {
	needSync := false
	var key string

	podObj, ok := obj.(*corev1.Pod)
	if !ok {
		metrics.SendErrorLogAndMetric(util.PodID, "ADD Pod: Received unexpected object type: %v", obj)
		return key, needSync
	}

	if !hasValidPodIP(podObj) {
		return key, needSync
	}

	if isHostNetworkPod(podObj) {
		return key, needSync
	}

	var err error
	if key, err = cache.MetaNamespaceKeyFunc(obj); err != nil {
		utilruntime.HandleError(err)
		metrics.SendErrorLogAndMetric(util.PodID, "[POD %s EVENT] Error: podKey is empty for %s pod in %s with UID %s",
			eventType, podObj.Name, util.GetNSNameWithPrefix(podObj.Namespace), podObj.UID)
		return key, needSync
	}

	needSync = true
	return key, needSync
}

func (c *PodController) addPod(obj interface{}) {
	key, needSync := c.needSync("ADD", obj)
	if !needSync {
		return
	}
	podObj, _ := obj.(*corev1.Pod)

	if !isValidPod(podObj) {
		return
	}

	// To check whether this pod is needed to queue or not.
	// If the pod are in completely terminated states, the pod is not enqueued to avoid unnecessary computation.
	if isCompletePod(podObj) {
		return
	}

	c.workqueue.Add(key)
}

func (c *PodController) updatePod(old, newp interface{}) {
	key, needSync := c.needSync("UPDATE", newp)
	if !needSync {
		return
	}

	// needSync checked validation of casting newPod.
	newPod, _ := newp.(*corev1.Pod)
	oldPod, ok := old.(*corev1.Pod)


	if !isValidPod(newPod) {
		return
	}

	if ok {
		if oldPod.ResourceVersion == newPod.ResourceVersion {
			// Periodic resync will send update events for all known pods.
			// Two different versions of the same pods will always have different RVs.
			return
		}
	}

	c.workqueue.Add(key)
}

func (c *PodController) deletePod(obj interface{}) {
	podObj, ok := obj.(*corev1.Pod)
	// DeleteFunc gets the final state of the resource (if it is known).
	// Otherwise, it gets an object of type DeletedFinalStateUnknown.
	// This can happen if the watch is closed and misses the delete event and
	// the controller doesn't notice the deletion until the subsequent re-list
	if !ok {
		tombstone, ok := obj.(cache.DeletedFinalStateUnknown)
		if !ok {
			metrics.SendErrorLogAndMetric(util.PodID, "[POD DELETE EVENT] Pod: Received unexpected object type: %v", obj)
			return
		}

		if podObj, ok = tombstone.Obj.(*corev1.Pod); !ok {
			metrics.SendErrorLogAndMetric(util.PodID, "[POD DELETE EVENT] Pod: Received unexpected object type (error decoding object tombstone, invalid type): %v", obj)
			return
		}
	}

	klog.Infof("[POD DELETE EVENT] for %s in %s", podObj.Name, podObj.Namespace)
	if isHostNetworkPod(podObj) {
		return
	}

	if !isValidPod(podObj) {
		return
	}

	var err error
	var key string
	if key, err = cache.MetaNamespaceKeyFunc(podObj); err != nil {
		utilruntime.HandleError(err)
		metrics.SendErrorLogAndMetric(util.PodID, "[POD DELETE EVENT] Error: podKey is empty for %s pod in %s with UID %s",
			podObj.ObjectMeta.Name, util.GetNSNameWithPrefix(podObj.Namespace), podObj.UID)
		return
	}

	c.workqueue.Add(key)
}

func (c *PodController) Run(stopCh <-chan struct{}) {
	defer utilruntime.HandleCrash()
	defer c.workqueue.ShutDown()

	klog.Infof("Starting Pod worker")
	go wait.Until(c.runWorker, time.Second, stopCh)

	klog.Info("Started Pod workers")
	<-stopCh
	klog.Info("Shutting down Pod workers")
}

func (c *PodController) runWorker() {
	for c.processNextWorkItem() {
	}
}

func (c *PodController) processNextWorkItem() bool {
	obj, shutdown := c.workqueue.Get()

	if shutdown {
		return false
	}

	err := func(obj interface{}) error {
		defer c.workqueue.Done(obj)
		var key string
		var ok bool
		if key, ok = obj.(string); !ok {
			// As the item in the workqueue is actually invalid, we call
			// Forget here else we'd go into a loop of attempting to
			// process a work item that is invalid.
			c.workqueue.Forget(obj)
			utilruntime.HandleError(fmt.Errorf("expected string in workqueue got %#v, err %w", obj, errWorkqueueFormatting))
			return nil
		}
		// Run the syncPod, passing it the namespace/name string of the
		// Pod resource to be synced.
		if err := c.syncPod(key); err != nil {
			// Put the item back on the workqueue to handle any transient errors.
			c.workqueue.AddRateLimited(key)
			metrics.SendErrorLogAndMetric(util.PodID, "[podController processNextWorkItem] Error: failed to syncPod %s. Requeuing with err: %v", key, err)
			return fmt.Errorf("error syncing '%s': %w, requeuing", key, err)
		}
		// Finally, if no error occurs we Forget this item so it does not
		// get queued again until another change happens.
		c.workqueue.Forget(obj)
		klog.Infof("Successfully synced '%s'", key)
		return nil
	}(obj)
	if err != nil {
		utilruntime.HandleError(err)
		return true
	}

	return true
}

// syncPod compares the actual state with the desired, and attempts to converge the two.
func (c *PodController) syncPod(key string) error {

	// Convert the namespace/name string into a distinct namespace and name
	namespace, name, err := cache.SplitMetaNamespaceKey(key)
	if err != nil {
		utilruntime.HandleError(fmt.Errorf("failed to split meta namespace key %s with err %w", key, err))
		return nil //nolint HandleError  is used instead of returning error to caller
	}

	// Get the Pod resource with this namespace/name
	pod, err := c.podLister.Pods(namespace).Get(name)

	c.Lock()
	defer c.Unlock()

	if err != nil {
		if apierrors.IsNotFound(err) {
			klog.Infof("pod %s not found, may be it is deleted", key)

			// cleanUpDeletedPod will check if the pod exists in cache, if it does then proceeds with deletion
			// if it does not exists, then event will be no-op
			err = c.cleanUpDeletedPod(key)
			if err != nil {
				// need to retry this cleaning-up process
				return fmt.Errorf("Error: %w when pod is not found", err)
			}
			return err
		}

		return err
	}

	// If this pod is completely in terminated states (which means pod is gracefully shutdown),
	// NPM starts clean-up the lastly applied states even in update events.
	// This proactive clean-up helps to miss stale pod object in case delete event is missed.
	if isCompletePod(pod) {
		if err = c.cleanUpDeletedPod(key); err != nil {
			return fmt.Errorf("Error: %w when when pod is in completed state", err)
		}
		return nil
	}

	cachedNpmPod, npmPodExists := c.podMap[key]
	if npmPodExists {
		// if pod does not have different states against lastly applied states stored in cachedNpmPod,
		// podController does not need to reconcile this update.
		// in this updatePod event, newPod was updated with states which PodController does not need to reconcile.
		if cachedNpmPod.noUpdate(pod) {
			return nil
		}
	}

	_, err = c.syncAddAndUpdatePod(pod)
	if err != nil {
		return fmt.Errorf("Failed to sync pod due to %w", err)
	}

	return nil
}

func (c *PodController) syncAddedPod(podObj *corev1.Pod) error {
	klog.Infof("POD CREATING: [%s/%s/%s/%s/%+v/%s]", string(podObj.GetUID()), podObj.Namespace,
		podObj.Name, podObj.Spec.NodeName, podObj.Labels, podObj.Status.PodIP)

	if !util.IsIPV4(podObj.Status.PodIP) {
		msg := fmt.Sprintf("[syncAddedPod] Error: ADD POD  [%s/%s/%s/%+v/%s] failed as the PodIP is not valid ipv4 address", podObj.Namespace,
			podObj.Name, podObj.Spec.NodeName, podObj.Labels, podObj.Status.PodIP)
		metrics.SendErrorLogAndMetric(util.PodID, msg)
		return npmerrors.Errorf(npmerrors.AddPod, true, msg)
	}

	podKey, _ := cache.MetaNamespaceKeyFunc(podObj)

	//podMetadata := dataplane.NewPodMetadata(podKey, podObj.Status.PodIP, podObj.Spec.NodeName)

	labelIDState := dp.GetIDs()

	// Create npmPod and add it to the podMap
	npmPodObj := newNpmPod(podObj)
	c.podMap[podKey] = npmPodObj
	labelValue := ""
	// Get lists of podLabelKey and podLabelKey + podLavelValue ,and then start adding them to ipsets.
	for labelKey, labelVal := range podObj.Labels {
		npmPodObj.appendLabels(map[string]string{labelKey: labelVal}, appendToExistingLabels)
		if labelKey == "role" {
			labelValue = labelVal
			break
		}
	}

	keyForID := fmt.Sprintf("%s:%s", podObj.Namespace, labelValue)
	idOfPod := labelIDState[keyForID]

	err_code := dp.InsertPodID(idOfPod, podObj.Status.PodIP)
	if err_code < 0 {
		return fmt.Errorf("Error: while updating the pod id into bpf map, ID: %d,IP: %s", idOfPod, podObj.Status.PodIP)
	}

	return nil
}

// syncAddAndUpdatePod handles updating pod ip in its label's ipset.
func (c *PodController) syncAddAndUpdatePod(newPodObj *corev1.Pod) (metrics.OperationKind, error) {
	podKey, _ := cache.MetaNamespaceKeyFunc(newPodObj)

	_, exists := c.podMap[podKey]
	klog.Infof("[syncAddAndUpdatePod] updating Pod with key %s", podKey)
	// No cached npmPod exists. start adding the pod in a cache
	if !exists {
		return metrics.CreateOp, c.syncAddedPod(newPodObj)
	}

	return metrics.UpdateOp, nil
}

// cleanUpDeletedPod cleans up all ipset associated with this pod
func (c *PodController) cleanUpDeletedPod(cachedNpmPodKey string) error {
	klog.Infof("[cleanUpDeletedPod] deleting Pod with key %s", cachedNpmPodKey)
	// If cached npmPod does not exist, return nil
	_, exist := c.podMap[cachedNpmPodKey]
	if !exist {
		return nil
	}

	delete(c.podMap, cachedNpmPodKey)
	return nil
}

// isCompletePod evaluates whether this pod is completely in terminated states,
// which means pod is gracefully shutdown.
func isCompletePod(podObj *corev1.Pod) bool {
	// DeletionTimestamp and DeletionGracePeriodSeconds in pod are not nil,
	// which means pod is expected to be deleted and
	// DeletionGracePeriodSeconds value is zero, which means the pod is gracefully terminated.
	if podObj.DeletionTimestamp != nil && podObj.DeletionGracePeriodSeconds != nil && *podObj.DeletionGracePeriodSeconds == 0 {
		return true
	}

	// K8s categorizes Succeeded and Failed pods as a terminated pod and will not restart them.
	// So NPM will ignorer adding these pods
	// TODO(jungukcho): what are the values of DeletionTimestamp and podObj.DeletionGracePeriodSeconds
	// in either below status?
	if podObj.Status.Phase == corev1.PodSucceeded || podObj.Status.Phase == corev1.PodFailed {
		return true
	}
	return false
}

func hasValidPodIP(podObj *corev1.Pod) bool {
	return len(podObj.Status.PodIP) > 0
}

func isHostNetworkPod(podObj *corev1.Pod) bool {
	return podObj.Spec.HostNetwork
}

func getContainerPortList(podObj *corev1.Pod) []corev1.ContainerPort {
	portList := []corev1.ContainerPort{}
	for i := range podObj.Spec.Containers {
		portList = append(portList, podObj.Spec.Containers[i].Ports...)
	}
	return portList
}

func isValidPod(podObj *corev1.Pod) bool {
	return podObj.Namespace == "x" || podObj.Namespace == "y" || podObj.Namespace == "z" 
}