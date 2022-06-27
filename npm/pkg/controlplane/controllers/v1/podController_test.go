// Copyright 2018 Microsoft. All rights reserved.
// MIT License
package controllers

import (
	"encoding/json"
	"fmt"
	"reflect"
	"strconv"
	"testing"

	"github.com/Azure/azure-container-networking/npm/ipsm"
	"github.com/Azure/azure-container-networking/npm/metrics"
	"github.com/Azure/azure-container-networking/npm/metrics/promutil"
	"github.com/Azure/azure-container-networking/npm/pkg/controlplane/controllers/common"
	"github.com/Azure/azure-container-networking/npm/util"
	testutils "github.com/Azure/azure-container-networking/test/utils"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	kubeinformers "k8s.io/client-go/informers"
	k8sfake "k8s.io/client-go/kubernetes/fake"
	core "k8s.io/client-go/testing"
	"k8s.io/client-go/tools/cache"
	utilexec "k8s.io/utils/exec"
	fakeexec "k8s.io/utils/exec/testing"
)

const (
	HostNetwork    = true
	NonHostNetwork = false
)

// To indicate the object is needed to be DeletedFinalStateUnknown Object
type IsDeletedFinalStateUnknownObject bool

const (
	DeletedFinalStateUnknownObject IsDeletedFinalStateUnknownObject = true
	DeletedFinalStateknownObject   IsDeletedFinalStateUnknownObject = false
)

type podFixture struct {
	t *testing.T

	// Objects to put in the store.
	podLister []*corev1.Pod
	// (TODO) Actions expected to happen on the client. Will use this to check action.
	kubeactions []core.Action
	// Objects from here preloaded into NewSimpleFake.
	kubeobjects []runtime.Object

	ipsMgr        *ipsm.IpsetManager
	podController *PodController
	kubeInformer  kubeinformers.SharedInformerFactory
}

func newFixture(t *testing.T, exec utilexec.Interface) *podFixture {
	f := &podFixture{
		t:           t,
		podLister:   []*corev1.Pod{},
		kubeobjects: []runtime.Object{},
		ipsMgr:      ipsm.NewIpsetManager(exec),
	}
	return f
}

func getKey(obj interface{}, t *testing.T) string {
	key, err := cache.DeletionHandlingMetaNamespaceKeyFunc(obj)
	if err != nil {
		t.Errorf("Unexpected error getting key for obj %v: %v", obj, err)
		return ""
	}
	return key
}

func (f *podFixture) newPodController(stopCh chan struct{}) {
	kubeclient := k8sfake.NewSimpleClientset(f.kubeobjects...)
	f.kubeInformer = kubeinformers.NewSharedInformerFactory(kubeclient, noResyncPeriodFunc())

	npmNamespaceCache := &NpmNamespaceCache{NsMap: make(map[string]*common.Namespace)}
	f.podController = NewPodController(f.kubeInformer.Core().V1().Pods(), f.ipsMgr, npmNamespaceCache)

	for _, pod := range f.podLister {
		f.kubeInformer.Core().V1().Pods().Informer().GetIndexer().Add(pod)
	}

	metrics.ReinitializeAll()

	// Do not start informer to avoid unnecessary event triggers
	// (TODO): Leave stopCh and below commented code to enhance UTs to even check event triggers as well later if possible
	// f.kubeInformer.Start(stopCh)
}

func createPod(name, ns, rv, podIP string, labels map[string]string, isHostNetwork bool, podPhase corev1.PodPhase) *corev1.Pod {
	return &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:            name,
			Namespace:       ns,
			Labels:          labels,
			ResourceVersion: rv,
		},
		Spec: corev1.PodSpec{
			HostNetwork: isHostNetwork,
			Containers: []corev1.Container{
				{
					Ports: []corev1.ContainerPort{
						{
							Name:          fmt.Sprintf("app:%s", name),
							ContainerPort: 8080,
							// Protocol:      "TCP",
						},
					},
				},
			},
		},
		Status: corev1.PodStatus{
			Phase: podPhase,
			PodIP: podIP,
		},
	}
}

func addPod(t *testing.T, f *podFixture, podObj *corev1.Pod) {
	// simulate pod add event and add pod object to sharedInformer cache
	f.podController.addPod(podObj)

	if f.podController.workqueue.Len() == 0 {
		t.Logf("Add Pod: worker queue length is 0 ")
		return
	}

	f.podController.processNextWorkItem()
}

func deletePod(t *testing.T, f *podFixture, podObj *corev1.Pod, isDeletedFinalStateUnknownObject IsDeletedFinalStateUnknownObject) {
	addPod(t, f, podObj)
	t.Logf("Complete add pod event")

	// simulate pod delete event and delete pod object from sharedInformer cache
	f.kubeInformer.Core().V1().Pods().Informer().GetIndexer().Delete(podObj)

	if isDeletedFinalStateUnknownObject {
		podKey := getKey(podObj, t)
		tombstone := cache.DeletedFinalStateUnknown{
			Key: podKey,
			Obj: podObj,
		}
		f.podController.deletePod(tombstone)
	} else {
		f.podController.deletePod(podObj)
	}

	if f.podController.workqueue.Len() == 0 {
		t.Logf("Delete Pod: worker queue length is 0 ")
		return
	}

	f.podController.processNextWorkItem()
}

// Need to make more cases - interestings..
func updatePod(t *testing.T, f *podFixture, oldPodObj *corev1.Pod, newPodObj *corev1.Pod) {
	addPod(t, f, oldPodObj)
	t.Logf("Complete add pod event")

	// simulate pod update event and update the pod to shared informer's cache
	f.kubeInformer.Core().V1().Pods().Informer().GetIndexer().Update(newPodObj)
	f.podController.updatePod(oldPodObj, newPodObj)

	if f.podController.workqueue.Len() == 0 {
		t.Logf("Update Pod: worker queue length is 0 ")
		return
	}

	f.podController.processNextWorkItem()
}

type expectedValues struct {
	expectedLenOfPodMap    int
	expectedLenOfNsMap     int
	expectedLenOfWorkQueue int
	podPromVals
}

type podPromVals struct {
	expectedAddExecCount    int
	expectedUpdateExecCount int
	expectedDeleteExecCount int
}

func (p *podPromVals) testPrometheusMetrics(t *testing.T) {
	addExecCount, err := metrics.GetControllerPodExecCount(metrics.CreateOp, false)
	promutil.NotifyIfErrors(t, err)
	require.Equal(t, p.expectedAddExecCount, addExecCount, "Count for add execution time didn't register correctly in Prometheus")

	addErrorExecCount, err := metrics.GetControllerPodExecCount(metrics.CreateOp, true)
	promutil.NotifyIfErrors(t, err)
	require.Equal(t, 0, addErrorExecCount, "Count for add error execution time should be 0")

	updateExecCount, err := metrics.GetControllerPodExecCount(metrics.UpdateOp, false)
	promutil.NotifyIfErrors(t, err)
	require.Equal(t, p.expectedUpdateExecCount, updateExecCount, "Count for update execution time didn't register correctly in Prometheus")

	updateErrorExecCount, err := metrics.GetControllerPodExecCount(metrics.UpdateOp, true)
	promutil.NotifyIfErrors(t, err)
	require.Equal(t, 0, updateErrorExecCount, "Count for update error execution time should be 0")

	deleteExecCount, err := metrics.GetControllerPodExecCount(metrics.DeleteOp, false)
	promutil.NotifyIfErrors(t, err)
	require.Equal(t, p.expectedDeleteExecCount, deleteExecCount, "Count for delete execution time didn't register correctly in Prometheus")

	deleteErrorExecCount, err := metrics.GetControllerPodExecCount(metrics.DeleteOp, true)
	promutil.NotifyIfErrors(t, err)
	require.Equal(t, 0, deleteErrorExecCount, "Count for delete error execution time should be 0")
}

func checkPodTestResult(testName string, f *podFixture, testCases []expectedValues) {
	for _, test := range testCases {
		if got := len(f.podController.podMap); got != test.expectedLenOfPodMap {
			f.t.Errorf("%s failed @ PodMap length = %d, want %d", testName, got, test.expectedLenOfPodMap)
		}
		if got := len(f.podController.npmNamespaceCache.NsMap); got != test.expectedLenOfNsMap {
			f.t.Errorf("%s failed @ NsMap length = %d, want %d", testName, got, test.expectedLenOfNsMap)
		}
		if got := f.podController.workqueue.Len(); got != test.expectedLenOfWorkQueue {
			f.t.Errorf("%s failed @ Workqueue length = %d, want %d", testName, got, test.expectedLenOfWorkQueue)
		}
		test.podPromVals.testPrometheusMetrics(f.t)
	}
}

func checkNpmPodWithInput(testName string, f *podFixture, inputPodObj *corev1.Pod) {
	podKey := getKey(inputPodObj, f.t)
	cachedNpmPodObj := f.podController.podMap[podKey]

	if cachedNpmPodObj.PodIP != inputPodObj.Status.PodIP {
		f.t.Errorf("%s failed @ PodIp check got = %s, want %s", testName, cachedNpmPodObj.PodIP, inputPodObj.Status.PodIP)
	}

	if !reflect.DeepEqual(cachedNpmPodObj.Labels, inputPodObj.Labels) {
		f.t.Errorf("%s failed @ Labels check got = %v, want %v", testName, cachedNpmPodObj.Labels, inputPodObj.Labels)
	}

	inputPortList := common.GetContainerPortList(inputPodObj)
	if !reflect.DeepEqual(cachedNpmPodObj.ContainerPorts, inputPortList) {
		f.t.Errorf("%s failed @ Container port check got = %v, want %v", testName, cachedNpmPodObj.PodIP, inputPortList)
	}
}

func TestAddMultiplePods(t *testing.T) {
	labels := map[string]string{
		"app": "test-pod",
	}
	podObj1 := createPod("test-pod-1", "test-namespace", "0", "1.2.3.4", labels, NonHostNetwork, corev1.PodRunning)
	podObj2 := createPod("test-pod-2", "test-namespace", "0", "1.2.3.5", labels, NonHostNetwork, corev1.PodRunning)

	calls := []testutils.TestCmd{
		{Cmd: []string{"ipset", "-N", "-exist", util.GetHashedName("ns-test-namespace"), "nethash"}},
		{Cmd: []string{"ipset", "-N", "-exist", util.GetHashedName("all-namespaces"), "setlist"}},
		{Cmd: []string{"ipset", "-A", "-exist", util.GetHashedName("all-namespaces"), util.GetHashedName("ns-test-namespace")}},
		{Cmd: []string{"ipset", "-A", "-exist", util.GetHashedName("ns-test-namespace"), "1.2.3.4"}},
		{Cmd: []string{"ipset", "-N", "-exist", util.GetHashedName("app"), "nethash"}},
		{Cmd: []string{"ipset", "-A", "-exist", util.GetHashedName("app"), "1.2.3.4"}},
		{Cmd: []string{"ipset", "-N", "-exist", util.GetHashedName("app:test-pod"), "nethash"}},
		{Cmd: []string{"ipset", "-A", "-exist", util.GetHashedName("app:test-pod"), "1.2.3.4"}},
		{Cmd: []string{"ipset", "-N", "-exist", util.GetHashedName("namedport:app:test-pod-1"), "hash:ip,port"}},
		{Cmd: []string{"ipset", "-A", "-exist", util.GetHashedName("namedport:app:test-pod-1"), "1.2.3.4,8080"}},
		{Cmd: []string{"ipset", "-A", "-exist", util.GetHashedName("ns-test-namespace"), "1.2.3.5"}},
		{Cmd: []string{"ipset", "-A", "-exist", util.GetHashedName("app"), "1.2.3.5"}},
		{Cmd: []string{"ipset", "-A", "-exist", util.GetHashedName("app:test-pod"), "1.2.3.5"}},
		{Cmd: []string{"ipset", "-N", "-exist", util.GetHashedName("namedport:app:test-pod-2"), "hash:ip,port"}},
		{Cmd: []string{"ipset", "-A", "-exist", util.GetHashedName("namedport:app:test-pod-2"), "1.2.3.5,8080"}},
	}

	fexec := testutils.GetFakeExecWithScripts(calls)
	defer testutils.VerifyCalls(t, fexec, calls)

	f := newFixture(t, fexec)
	f.podLister = append(f.podLister, podObj1, podObj2)
	f.kubeobjects = append(f.kubeobjects, podObj1, podObj2)
	stopCh := make(chan struct{})
	defer close(stopCh)
	f.newPodController(stopCh)

	addPod(t, f, podObj1)
	addPod(t, f, podObj2)

	// already exists (will be a no-op)
	addPod(t, f, podObj1)

	testCases := []expectedValues{
		{2, 1, 0, podPromVals{2, 0, 0}},
	}
	checkPodTestResult("TestAddMultiplePods", f, testCases)
	checkNpmPodWithInput("TestAddMultiplePods", f, podObj1)
	checkNpmPodWithInput("TestAddMultiplePods", f, podObj2)
}

func TestAddPod(t *testing.T) {
	labels := map[string]string{
		"app": "test-pod",
	}
	podObj := createPod("test-pod", "test-namespace", "0", "1.2.3.4", labels, NonHostNetwork, corev1.PodRunning)

	calls := []testutils.TestCmd{
		{Cmd: []string{"ipset", "-N", "-exist", util.GetHashedName("ns-test-namespace"), "nethash"}},
		{Cmd: []string{"ipset", "-N", "-exist", util.GetHashedName("all-namespaces"), "setlist"}},
		{Cmd: []string{"ipset", "-A", "-exist", util.GetHashedName("all-namespaces"), util.GetHashedName("ns-test-namespace")}},
		{Cmd: []string{"ipset", "-A", "-exist", util.GetHashedName("ns-test-namespace"), "1.2.3.4"}},
		{Cmd: []string{"ipset", "-N", "-exist", util.GetHashedName("app"), "nethash"}},
		{Cmd: []string{"ipset", "-A", "-exist", util.GetHashedName("app"), "1.2.3.4"}},
		{Cmd: []string{"ipset", "-N", "-exist", util.GetHashedName("app:test-pod"), "nethash"}},
		{Cmd: []string{"ipset", "-A", "-exist", util.GetHashedName("app:test-pod"), "1.2.3.4"}},
		{Cmd: []string{"ipset", "-N", "-exist", util.GetHashedName("namedport:app:test-pod"), "hash:ip,port"}},
		{Cmd: []string{"ipset", "-A", "-exist", util.GetHashedName("namedport:app:test-pod"), "1.2.3.4,8080"}},
	}

	fexec := testutils.GetFakeExecWithScripts(calls)
	defer testutils.VerifyCalls(t, fexec, calls)

	f := newFixture(t, fexec)
	f.podLister = append(f.podLister, podObj)
	f.kubeobjects = append(f.kubeobjects, podObj)
	stopCh := make(chan struct{})
	defer close(stopCh)
	f.newPodController(stopCh)

	addPod(t, f, podObj)
	testCases := []expectedValues{
		{1, 1, 0, podPromVals{1, 0, 0}},
	}
	checkPodTestResult("TestAddPod", f, testCases)
	checkNpmPodWithInput("TestAddPod", f, podObj)
}

func TestAddHostNetworkPod(t *testing.T) {
	labels := map[string]string{
		"app": "test-pod",
	}
	podObj := createPod("test-pod", "test-namespace", "0", "1.2.3.4", labels, HostNetwork, corev1.PodRunning)
	podKey := getKey(podObj, t)

	calls := []testutils.TestCmd{}

	fexec := testutils.GetFakeExecWithScripts(calls)
	defer testutils.VerifyCalls(t, fexec, calls)

	f := newFixture(t, fexec)
	f.podLister = append(f.podLister, podObj)
	f.kubeobjects = append(f.kubeobjects, podObj)
	stopCh := make(chan struct{})
	defer close(stopCh)
	f.newPodController(stopCh)

	addPod(t, f, podObj)
	// host network pods are ignored, so prometheus exec counts will be 0
	testCases := []expectedValues{
		{0, 0, 0, podPromVals{0, 0, 0}},
	}
	checkPodTestResult("TestAddHostNetworkPod", f, testCases)

	if _, exists := f.podController.podMap[podKey]; exists {
		t.Error("TestAddHostNetworkPod failed @ cached pod obj exists check")
	}
}

func TestDeletePod(t *testing.T) {
	labels := map[string]string{
		"app": "test-pod",
	}
	podObj := createPod("test-pod", "test-namespace", "0", "1.2.3.4", labels, NonHostNetwork, corev1.PodRunning)
	podKey := getKey(podObj, t)

	calls := []testutils.TestCmd{
		// add pod
		{Cmd: []string{"ipset", "-N", "-exist", util.GetHashedName("ns-test-namespace"), "nethash"}},
		{Cmd: []string{"ipset", "-N", "-exist", util.GetHashedName("all-namespaces"), "setlist"}},
		{Cmd: []string{"ipset", "-A", "-exist", util.GetHashedName("all-namespaces"), util.GetHashedName("ns-test-namespace")}},
		{Cmd: []string{"ipset", "-A", "-exist", util.GetHashedName("ns-test-namespace"), "1.2.3.4"}},
		{Cmd: []string{"ipset", "-N", "-exist", util.GetHashedName("app"), "nethash"}},
		{Cmd: []string{"ipset", "-A", "-exist", util.GetHashedName("app"), "1.2.3.4"}},
		{Cmd: []string{"ipset", "-N", "-exist", util.GetHashedName("app:test-pod"), "nethash"}},
		{Cmd: []string{"ipset", "-A", "-exist", util.GetHashedName("app:test-pod"), "1.2.3.4"}},
		{Cmd: []string{"ipset", "-N", "-exist", util.GetHashedName("namedport:app:test-pod"), "hash:ip,port"}},
		{Cmd: []string{"ipset", "-A", "-exist", util.GetHashedName("namedport:app:test-pod"), "1.2.3.4,8080"}},

		// delete pod
		{Cmd: []string{"ipset", "-D", "-exist", util.GetHashedName("ns-test-namespace"), "1.2.3.4"}},
		{Cmd: []string{"ipset", "-X", "-exist", util.GetHashedName("ns-test-namespace")}},
		{Cmd: []string{"ipset", "-D", "-exist", util.GetHashedName("app"), "1.2.3.4"}},
		{Cmd: []string{"ipset", "-X", "-exist", util.GetHashedName("app")}},
		{Cmd: []string{"ipset", "-D", "-exist", util.GetHashedName("app:test-pod"), "1.2.3.4"}},
		{Cmd: []string{"ipset", "-X", "-exist", util.GetHashedName("app:test-pod")}},
		{Cmd: []string{"ipset", "-D", "-exist", util.GetHashedName("namedport:app:test-pod"), "1.2.3.4,8080"}},
		{Cmd: []string{"ipset", "-X", "-exist", util.GetHashedName("namedport:app:test-pod")}},
	}

	fexec := testutils.GetFakeExecWithScripts(calls)
	defer testutils.VerifyCalls(t, fexec, calls)

	f := newFixture(t, fexec)
	f.podLister = append(f.podLister, podObj)
	f.kubeobjects = append(f.kubeobjects, podObj)
	stopCh := make(chan struct{})
	defer close(stopCh)
	f.newPodController(stopCh)

	deletePod(t, f, podObj, DeletedFinalStateknownObject)
	testCases := []expectedValues{
		{0, 1, 0, podPromVals{1, 0, 1}},
	}

	checkPodTestResult("TestDeletePod", f, testCases)
	if _, exists := f.podController.podMap[podKey]; exists {
		t.Error("TestDeletePod failed @ cached pod obj exists check")
	}
}

func TestDeleteHostNetworkPod(t *testing.T) {
	labels := map[string]string{
		"app": "test-pod",
	}
	podObj := createPod("test-pod", "test-namespace", "0", "1.2.3.4", labels, HostNetwork, corev1.PodRunning)
	podKey := getKey(podObj, t)

	calls := []testutils.TestCmd{}

	fexec := testutils.GetFakeExecWithScripts(calls)
	defer testutils.VerifyCalls(t, fexec, calls)

	f := newFixture(t, fexec)
	f.podLister = append(f.podLister, podObj)
	f.kubeobjects = append(f.kubeobjects, podObj)
	stopCh := make(chan struct{})
	defer close(stopCh)
	f.newPodController(stopCh)

	deletePod(t, f, podObj, DeletedFinalStateknownObject)
	// host network pods are ignored, so prometheus exec counts will be
	testCases := []expectedValues{
		{0, 0, 0, podPromVals{0, 0, 0}},
	}
	checkPodTestResult("TestDeleteHostNetworkPod", f, testCases)
	if _, exists := f.podController.podMap[podKey]; exists {
		t.Error("TestDeleteHostNetworkPod failed @ cached pod obj exists check")
	}
}

// this UT only tests deletePod event handler function in podController
func TestDeletePodWithTombstone(t *testing.T) {
	labels := map[string]string{
		"app": "test-pod",
	}
	podObj := createPod("test-pod", "test-namespace", "0", "1.2.3.4", labels, NonHostNetwork, corev1.PodRunning)

	calls := []testutils.TestCmd{}

	fexec := testutils.GetFakeExecWithScripts(calls)
	defer testutils.VerifyCalls(t, fexec, calls)

	f := newFixture(t, fexec)
	stopCh := make(chan struct{})
	defer close(stopCh)
	f.newPodController(stopCh)

	podKey := getKey(podObj, t)
	tombstone := cache.DeletedFinalStateUnknown{
		Key: podKey,
		Obj: podObj,
	}

	f.podController.deletePod(tombstone)
	// the above function only adds to the workqueue
	testCases := []expectedValues{
		{0, 0, 1, podPromVals{0, 0, 0}},
	}
	checkPodTestResult("TestDeletePodWithTombstone", f, testCases)
}

func TestDeletePodWithTombstoneAfterAddingPod(t *testing.T) {
	labels := map[string]string{
		"app": "test-pod",
	}
	podObj := createPod("test-pod", "test-namespace", "0", "1.2.3.4", labels, NonHostNetwork, corev1.PodRunning)

	calls := []testutils.TestCmd{
		// add pod
		{Cmd: []string{"ipset", "-N", "-exist", util.GetHashedName("ns-test-namespace"), "nethash"}},
		{Cmd: []string{"ipset", "-N", "-exist", util.GetHashedName("all-namespaces"), "setlist"}},
		{Cmd: []string{"ipset", "-A", "-exist", util.GetHashedName("all-namespaces"), util.GetHashedName("ns-test-namespace")}},
		{Cmd: []string{"ipset", "-A", "-exist", util.GetHashedName("ns-test-namespace"), "1.2.3.4"}},
		{Cmd: []string{"ipset", "-N", "-exist", util.GetHashedName("app"), "nethash"}},
		{Cmd: []string{"ipset", "-A", "-exist", util.GetHashedName("app"), "1.2.3.4"}},
		{Cmd: []string{"ipset", "-N", "-exist", util.GetHashedName("app:test-pod"), "nethash"}},
		{Cmd: []string{"ipset", "-A", "-exist", util.GetHashedName("app:test-pod"), "1.2.3.4"}},
		{Cmd: []string{"ipset", "-N", "-exist", util.GetHashedName("namedport:app:test-pod"), "hash:ip,port"}},
		{Cmd: []string{"ipset", "-A", "-exist", util.GetHashedName("namedport:app:test-pod"), "1.2.3.4,8080"}},

		// delete pod
		{Cmd: []string{"ipset", "-D", "-exist", util.GetHashedName("ns-test-namespace"), "1.2.3.4"}},
		{Cmd: []string{"ipset", "-X", "-exist", util.GetHashedName("ns-test-namespace")}},
		{Cmd: []string{"ipset", "-D", "-exist", util.GetHashedName("app"), "1.2.3.4"}},
		{Cmd: []string{"ipset", "-X", "-exist", util.GetHashedName("app")}},
		{Cmd: []string{"ipset", "-D", "-exist", util.GetHashedName("app:test-pod"), "1.2.3.4"}},
		{Cmd: []string{"ipset", "-X", "-exist", util.GetHashedName("app:test-pod")}},
		{Cmd: []string{"ipset", "-D", "-exist", util.GetHashedName("namedport:app:test-pod"), "1.2.3.4,8080"}},
		{Cmd: []string{"ipset", "-X", "-exist", util.GetHashedName("namedport:app:test-pod")}},
	}

	fexec := testutils.GetFakeExecWithScripts(calls)
	defer testutils.VerifyCalls(t, fexec, calls)

	f := newFixture(t, fexec)
	f.podLister = append(f.podLister, podObj)
	f.kubeobjects = append(f.kubeobjects, podObj)
	stopCh := make(chan struct{})
	defer close(stopCh)
	f.newPodController(stopCh)

	deletePod(t, f, podObj, DeletedFinalStateUnknownObject)
	testCases := []expectedValues{
		{0, 1, 0, podPromVals{1, 0, 1}},
	}
	checkPodTestResult("TestDeletePodWithTombstoneAfterAddingPod", f, testCases)
}

func TestLabelUpdatePod(t *testing.T) {
	labels := map[string]string{
		"app": "test-pod",
	}
	oldPodObj := createPod("test-pod", "test-namespace", "0", "1.2.3.4", labels, NonHostNetwork, corev1.PodRunning)

	calls := []testutils.TestCmd{
		// add pod
		{Cmd: []string{"ipset", "-N", "-exist", util.GetHashedName("ns-test-namespace"), "nethash"}},
		{Cmd: []string{"ipset", "-N", "-exist", util.GetHashedName("all-namespaces"), "setlist"}},
		{Cmd: []string{"ipset", "-A", "-exist", util.GetHashedName("all-namespaces"), util.GetHashedName("ns-test-namespace")}},
		{Cmd: []string{"ipset", "-A", "-exist", util.GetHashedName("ns-test-namespace"), "1.2.3.4"}},
		{Cmd: []string{"ipset", "-N", "-exist", util.GetHashedName("app"), "nethash"}},
		{Cmd: []string{"ipset", "-A", "-exist", util.GetHashedName("app"), "1.2.3.4"}},
		{Cmd: []string{"ipset", "-N", "-exist", util.GetHashedName("app:test-pod"), "nethash"}},
		{Cmd: []string{"ipset", "-A", "-exist", util.GetHashedName("app:test-pod"), "1.2.3.4"}},
		{Cmd: []string{"ipset", "-N", "-exist", util.GetHashedName("namedport:app:test-pod"), "hash:ip,port"}},
		{Cmd: []string{"ipset", "-A", "-exist", util.GetHashedName("namedport:app:test-pod"), "1.2.3.4,8080"}},

		// update pod
		{Cmd: []string{"ipset", "-D", "-exist", util.GetHashedName("app:test-pod"), "1.2.3.4"}},
		{Cmd: []string{"ipset", "-X", "-exist", util.GetHashedName("app:test-pod")}},
		{Cmd: []string{"ipset", "-N", "-exist", util.GetHashedName("app:new-test-pod"), "nethash"}},
		{Cmd: []string{"ipset", "-A", "-exist", util.GetHashedName("app:new-test-pod"), "1.2.3.4"}},
	}

	fexec := testutils.GetFakeExecWithScripts(calls)
	defer testutils.VerifyCalls(t, fexec, calls)

	f := newFixture(t, fexec)
	f.podLister = append(f.podLister, oldPodObj)
	f.kubeobjects = append(f.kubeobjects, oldPodObj)
	stopCh := make(chan struct{})
	defer close(stopCh)
	f.newPodController(stopCh)

	newPodObj := oldPodObj.DeepCopy()
	newPodObj.Labels = map[string]string{
		"app": "new-test-pod",
	}
	// oldPodObj.ResourceVersion value is "0"
	newRV, _ := strconv.Atoi(oldPodObj.ResourceVersion)
	newPodObj.ResourceVersion = fmt.Sprintf("%d", newRV+1)
	updatePod(t, f, oldPodObj, newPodObj)

	testCases := []expectedValues{
		{1, 1, 0, podPromVals{1, 1, 0}},
	}
	checkPodTestResult("TestLabelUpdatePod", f, testCases)
	checkNpmPodWithInput("TestLabelUpdatePod", f, newPodObj)
}

func TestIPAddressUpdatePod(t *testing.T) {
	labels := map[string]string{
		"app": "test-pod",
	}
	oldPodObj := createPod("test-pod", "test-namespace", "0", "1.2.3.4", labels, NonHostNetwork, corev1.PodRunning)

	calls := []testutils.TestCmd{
		// add pod
		{Cmd: []string{"ipset", "-N", "-exist", util.GetHashedName("ns-test-namespace"), "nethash"}},
		{Cmd: []string{"ipset", "-N", "-exist", util.GetHashedName("all-namespaces"), "setlist"}},
		{Cmd: []string{"ipset", "-A", "-exist", util.GetHashedName("all-namespaces"), util.GetHashedName("ns-test-namespace")}},
		{Cmd: []string{"ipset", "-A", "-exist", util.GetHashedName("ns-test-namespace"), "1.2.3.4"}},
		{Cmd: []string{"ipset", "-N", "-exist", util.GetHashedName("app"), "nethash"}},
		{Cmd: []string{"ipset", "-A", "-exist", util.GetHashedName("app"), "1.2.3.4"}},
		{Cmd: []string{"ipset", "-N", "-exist", util.GetHashedName("app:test-pod"), "nethash"}},
		{Cmd: []string{"ipset", "-A", "-exist", util.GetHashedName("app:test-pod"), "1.2.3.4"}},
		{Cmd: []string{"ipset", "-N", "-exist", util.GetHashedName("namedport:app:test-pod"), "hash:ip,port"}},
		{Cmd: []string{"ipset", "-A", "-exist", util.GetHashedName("namedport:app:test-pod"), "1.2.3.4,8080"}},

		// update pod
		{Cmd: []string{"ipset", "-D", "-exist", util.GetHashedName("ns-test-namespace"), "1.2.3.4"}},
		{Cmd: []string{"ipset", "-X", "-exist", util.GetHashedName("ns-test-namespace")}},
		{Cmd: []string{"ipset", "-D", "-exist", util.GetHashedName("app"), "1.2.3.4"}},
		{Cmd: []string{"ipset", "-X", "-exist", util.GetHashedName("app")}},
		{Cmd: []string{"ipset", "-D", "-exist", util.GetHashedName("app:test-pod"), "1.2.3.4"}},
		{Cmd: []string{"ipset", "-X", "-exist", util.GetHashedName("app:test-pod")}},
		{Cmd: []string{"ipset", "-D", "-exist", util.GetHashedName("namedport:app:test-pod"), "1.2.3.4,8080"}},
		{Cmd: []string{"ipset", "-X", "-exist", util.GetHashedName("namedport:app:test-pod")}},
		{Cmd: []string{"ipset", "-N", "-exist", util.GetHashedName("ns-test-namespace"), "nethash"}},
		{Cmd: []string{"ipset", "-A", "-exist", util.GetHashedName("ns-test-namespace"), "4.3.2.1"}},
		{Cmd: []string{"ipset", "-N", "-exist", util.GetHashedName("app"), "nethash"}},
		{Cmd: []string{"ipset", "-A", "-exist", util.GetHashedName("app"), "4.3.2.1"}},
		{Cmd: []string{"ipset", "-N", "-exist", util.GetHashedName("app:test-pod"), "nethash"}},
		{Cmd: []string{"ipset", "-A", "-exist", util.GetHashedName("app:test-pod"), "4.3.2.1"}},
		{Cmd: []string{"ipset", "-N", "-exist", util.GetHashedName("namedport:app:test-pod"), "hash:ip,port"}},
		{Cmd: []string{"ipset", "-A", "-exist", util.GetHashedName("namedport:app:test-pod"), "4.3.2.1,8080"}},
	}

	fexec := testutils.GetFakeExecWithScripts(calls)
	defer testutils.VerifyCalls(t, fexec, calls)

	f := newFixture(t, fexec)
	f.podLister = append(f.podLister, oldPodObj)
	f.kubeobjects = append(f.kubeobjects, oldPodObj)
	stopCh := make(chan struct{})
	defer close(stopCh)
	f.newPodController(stopCh)

	newPodObj := oldPodObj.DeepCopy()
	// oldPodObj.ResourceVersion value is "0"
	newRV, _ := strconv.Atoi(oldPodObj.ResourceVersion)
	newPodObj.ResourceVersion = fmt.Sprintf("%d", newRV+1)
	// oldPodObj PodIP is "1.2.3.4"
	newPodObj.Status.PodIP = "4.3.2.1"
	updatePod(t, f, oldPodObj, newPodObj)

	testCases := []expectedValues{
		{1, 1, 0, podPromVals{1, 1, 0}},
	}
	checkPodTestResult("TestIPAddressUpdatePod", f, testCases)
	checkNpmPodWithInput("TestIPAddressUpdatePod", f, newPodObj)
}

func TestPodStatusUpdatePod(t *testing.T) {
	labels := map[string]string{
		"app": "test-pod",
	}
	oldPodObj := createPod("test-pod", "test-namespace", "0", "1.2.3.4", labels, NonHostNetwork, corev1.PodRunning)
	podKey := getKey(oldPodObj, t)

	calls := []testutils.TestCmd{
		// add pod
		{Cmd: []string{"ipset", "-N", "-exist", util.GetHashedName("ns-test-namespace"), "nethash"}},
		{Cmd: []string{"ipset", "-N", "-exist", util.GetHashedName("all-namespaces"), "setlist"}},
		{Cmd: []string{"ipset", "-A", "-exist", util.GetHashedName("all-namespaces"), util.GetHashedName("ns-test-namespace")}},
		{Cmd: []string{"ipset", "-A", "-exist", util.GetHashedName("ns-test-namespace"), "1.2.3.4"}},
		{Cmd: []string{"ipset", "-N", "-exist", util.GetHashedName("app"), "nethash"}},
		{Cmd: []string{"ipset", "-A", "-exist", util.GetHashedName("app"), "1.2.3.4"}},
		{Cmd: []string{"ipset", "-N", "-exist", util.GetHashedName("app:test-pod"), "nethash"}},
		{Cmd: []string{"ipset", "-A", "-exist", util.GetHashedName("app:test-pod"), "1.2.3.4"}},
		{Cmd: []string{"ipset", "-N", "-exist", util.GetHashedName("namedport:app:test-pod"), "hash:ip,port"}},
		{Cmd: []string{"ipset", "-A", "-exist", util.GetHashedName("namedport:app:test-pod"), "1.2.3.4,8080"}},

		// update pod
		{Cmd: []string{"ipset", "-D", "-exist", util.GetHashedName("ns-test-namespace"), "1.2.3.4"}},
		{Cmd: []string{"ipset", "-X", "-exist", util.GetHashedName("ns-test-namespace")}},
		{Cmd: []string{"ipset", "-D", "-exist", util.GetHashedName("app"), "1.2.3.4"}},
		{Cmd: []string{"ipset", "-X", "-exist", util.GetHashedName("app")}},
		{Cmd: []string{"ipset", "-D", "-exist", util.GetHashedName("app:test-pod"), "1.2.3.4"}},
		{Cmd: []string{"ipset", "-X", "-exist", util.GetHashedName("app:test-pod")}},
		{Cmd: []string{"ipset", "-D", "-exist", util.GetHashedName("namedport:app:test-pod"), "1.2.3.4,8080"}},
		{Cmd: []string{"ipset", "-X", "-exist", util.GetHashedName("namedport:app:test-pod")}},
	}

	fexec := testutils.GetFakeExecWithScripts(calls)
	defer testutils.VerifyCalls(t, fexec, calls)

	f := newFixture(t, fexec)
	f.podLister = append(f.podLister, oldPodObj)
	f.kubeobjects = append(f.kubeobjects, oldPodObj)
	stopCh := make(chan struct{})
	defer close(stopCh)
	f.newPodController(stopCh)

	newPodObj := oldPodObj.DeepCopy()
	// oldPodObj.ResourceVersion value is "0"
	newRV, _ := strconv.Atoi(oldPodObj.ResourceVersion)
	newPodObj.ResourceVersion = fmt.Sprintf("%d", newRV+1)

	// oldPodObj PodIP is "1.2.3.4"
	newPodObj.Status.Phase = corev1.PodSucceeded
	updatePod(t, f, oldPodObj, newPodObj)

	// delete count is 1 because when the pod is succeeded, we delete the pods' info in ipsets
	testCases := []expectedValues{
		{0, 1, 0, podPromVals{1, 0, 1}},
	}
	checkPodTestResult("TestPodStatusUpdatePod", f, testCases)
	if _, exists := f.podController.podMap[podKey]; exists {
		t.Error("TestPodStatusUpdatePod failed @ cached pod obj exists check")
	}
}

func TestPodMapMarshalJSON(t *testing.T) {
	fexec := &fakeexec.FakeExec{}
	f := newFixture(t, fexec)
	stopCh := make(chan struct{})
	defer close(stopCh)
	f.newPodController(stopCh)

	labels := map[string]string{
		"app": "test-pod",
	}
	pod := createPod("test-pod", "test-namespace", "0", "1.2.3.4", labels, NonHostNetwork, corev1.PodRunning)
	podKey, err := cache.MetaNamespaceKeyFunc(pod)
	assert.NoError(t, err)

	npmPod := common.NewNpmPod(pod)
	f.podController.podMap[podKey] = npmPod

	npMapRaw, err := json.Marshal(f.podController)
	assert.NoError(t, err)

	expect := []byte(`{"test-namespace/test-pod":{"Name":"test-pod","Namespace":"test-namespace","PodIP":"1.2.3.4","Labels":{},"ContainerPorts":[],"Phase":"Running"}}`)
	fmt.Printf("%s\n", string(npMapRaw))
	assert.ElementsMatch(t, expect, npMapRaw)
}

func TestHasValidPodIP(t *testing.T) {
	podObj := &corev1.Pod{
		Status: corev1.PodStatus{
			Phase: "Running",
			PodIP: "1.2.3.4",
		},
	}
	if ok := hasValidPodIP(podObj); !ok {
		t.Errorf("TestisValidPod failed @ isValidPod")
	}
}

func TestIsCompletePod(t *testing.T) {
	var zeroGracePeriod int64
	var defaultGracePeriod int64 = 30

	type podState struct {
		phase                      corev1.PodPhase
		deletionTimestamp          *metav1.Time
		deletionGracePeriodSeconds *int64
	}

	tests := []struct {
		name                 string
		podState             podState
		expectedCompletedPod bool
	}{

		{
			name: "pod is in running status",
			podState: podState{
				phase:                      corev1.PodRunning,
				deletionTimestamp:          nil,
				deletionGracePeriodSeconds: nil,
			},
			expectedCompletedPod: false,
		},
		{
			name: "pod is in completely terminating states after graceful shutdown period",
			podState: podState{
				phase:                      corev1.PodRunning,
				deletionTimestamp:          &metav1.Time{},
				deletionGracePeriodSeconds: &zeroGracePeriod,
			},
			expectedCompletedPod: true,
		},
		{
			name: "pod is in terminating states, but in graceful shutdown period",
			podState: podState{
				phase:                      corev1.PodRunning,
				deletionTimestamp:          &metav1.Time{},
				deletionGracePeriodSeconds: &defaultGracePeriod,
			},
			expectedCompletedPod: false,
		},
		{
			name: "pod is in PodSucceeded status",
			podState: podState{
				phase:                      corev1.PodSucceeded,
				deletionTimestamp:          nil,
				deletionGracePeriodSeconds: nil,
			},
			expectedCompletedPod: true,
		},
		{
			name: "pod is in PodFailed status",
			podState: podState{
				phase:                      corev1.PodSucceeded,
				deletionTimestamp:          nil,
				deletionGracePeriodSeconds: nil,
			},
			expectedCompletedPod: true,
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			corev1Pod := &corev1.Pod{
				ObjectMeta: metav1.ObjectMeta{
					DeletionTimestamp:          tt.podState.deletionTimestamp,
					DeletionGracePeriodSeconds: tt.podState.deletionGracePeriodSeconds,
				},
				Status: corev1.PodStatus{
					Phase: tt.podState.phase,
				},
			}
			isPodCompleted := isCompletePod(corev1Pod)
			require.Equal(t, tt.expectedCompletedPod, isPodCompleted)
		})
	}
}

// Extra unit test which is not quite related to PodController,
// but help to understand how workqueue works to make event handler logic lock-free.
// If the same key are queued into workqueue in multiple times,
// they are combined into one item (accurately, if the item is not processed).
func TestWorkQueue(t *testing.T) {
	labels := map[string]string{
		"app": "test-pod",
	}
	podObj := createPod("test-pod", "test-namespace", "0", "1.2.3.4", labels, NonHostNetwork, corev1.PodRunning)

	fexec := testutils.GetFakeExecWithScripts([]testutils.TestCmd{})
	f := newFixture(t, fexec)

	f.podLister = append(f.podLister, podObj)
	f.kubeobjects = append(f.kubeobjects, podObj)
	stopCh := make(chan struct{})
	defer close(stopCh)
	f.newPodController(stopCh)

	podKeys := []string{"test-pod", "test-pod", "test-pod1"}
	expectedWorkQueueLength := []int{1, 1, 2}

	for idx, podKey := range podKeys {
		f.podController.workqueue.Add(podKey)
		workQueueLength := f.podController.workqueue.Len()
		if workQueueLength != expectedWorkQueueLength[idx] {
			t.Errorf("TestWorkQueue failed due to returned workqueue length = %d, want %d",
				workQueueLength, expectedWorkQueueLength)
		}
	}
}

func TestNPMPodNoUpdate(t *testing.T) {
	type podInfo struct {
		podName       string
		ns            string
		rv            string
		podIP         string
		labels        map[string]string
		isHostNetwork bool
		podPhase      corev1.PodPhase
	}

	labels := map[string]string{
		"app": "test-pod",
	}

	tests := []struct {
		name string
		podInfo
		updatingNPMPod   bool
		expectedNoUpdate bool
	}{
		{
			"Required update of NPMPod given Pod",
			podInfo{
				podName:       "test-pod-1",
				ns:            "test-namespace",
				rv:            "0",
				podIP:         "1.2.3.4",
				labels:        labels,
				isHostNetwork: NonHostNetwork,
				podPhase:      corev1.PodRunning,
			},
			false,
			false,
		},
		{
			"No required update of NPMPod given Pod",
			podInfo{
				podName:       "test-pod-2",
				ns:            "test-namespace",
				rv:            "0",
				podIP:         "1.2.3.4",
				labels:        labels,
				isHostNetwork: NonHostNetwork,
				podPhase:      corev1.PodRunning,
			},
			true,
			true,
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			corev1Pod := createPod(tt.podName, tt.ns, tt.rv, tt.podIP, tt.labels, tt.isHostNetwork, tt.podPhase)
			npmPod := common.NewNpmPod(corev1Pod)
			if tt.updatingNPMPod {
				npmPod.AppendLabels(corev1Pod.Labels, common.AppendToExistingLabels)
				npmPod.UpdateNpmPodAttributes(corev1Pod)
				npmPod.AppendContainerPorts(corev1Pod)
			}
			noUpdate := npmPod.NoUpdate(corev1Pod)
			require.Equal(t, tt.expectedNoUpdate, noUpdate)
		})
	}
}
