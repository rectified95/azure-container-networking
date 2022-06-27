package ipampool

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/Azure/azure-container-networking/cns"
	"github.com/Azure/azure-container-networking/cns/logger"
	"github.com/Azure/azure-container-networking/cns/metric"
	"github.com/Azure/azure-container-networking/cns/types"
	"github.com/Azure/azure-container-networking/crd/nodenetworkconfig/api/v1alpha"
	"github.com/pkg/errors"
)

const (
	// DefaultRefreshDelay pool monitor poll delay default in seconds.
	DefaultRefreshDelay = 1 * time.Second
	// DefaultMaxIPs default maximum allocatable IPs
	DefaultMaxIPs = 250
	// Subnet ARM ID /subscriptions/$(SUB)/resourceGroups/$(GROUP)/providers/Microsoft.Network/virtualNetworks/$(VNET)/subnets/$(SUBNET)
	subnetARMIDTemplate = "/subscriptions/%s/resourceGroups/%s/providers/Microsoft.Network/virtualNetworks/%s/subnets/%s"
)

type nodeNetworkConfigSpecUpdater interface {
	UpdateSpec(context.Context, *v1alpha.NodeNetworkConfigSpec) (*v1alpha.NodeNetworkConfig, error)
}

// metaState is the Monitor's configuration state for the IP pool.
type metaState struct {
	batch         int64
	max           int64
	maxFreeCount  int64
	minFreeCount  int64
	notInUseCount int64
}

type Options struct {
	RefreshDelay time.Duration
	MaxIPs       int64
}

type Monitor struct {
	opts        *Options
	spec        v1alpha.NodeNetworkConfigSpec
	metastate   metaState
	nnccli      nodeNetworkConfigSpecUpdater
	httpService cns.HTTPService
	started     chan interface{}
	nncSource   chan v1alpha.NodeNetworkConfig
	once        sync.Once
}

// Global Variables for Subnet, Subnet Address Space and Subnet ARM ID
var subnet, subnetCIDR, subnetARMID string

func NewMonitor(httpService cns.HTTPService, nnccli nodeNetworkConfigSpecUpdater, opts *Options) *Monitor {
	if opts.RefreshDelay < 1 {
		opts.RefreshDelay = DefaultRefreshDelay
	}
	if opts.MaxIPs < 1 {
		opts.MaxIPs = DefaultMaxIPs
	}
	return &Monitor{
		opts:        opts,
		httpService: httpService,
		nnccli:      nnccli,
		started:     make(chan interface{}),
		nncSource:   make(chan v1alpha.NodeNetworkConfig),
	}
}

// Start begins the Monitor's pool reconcile loop.
// On first run, it will block until a NodeNetworkConfig is received (through a call to Update()).
// Subsequently, it will run run once per RefreshDelay and attempt to re-reconcile the pool.
func (pm *Monitor) Start(ctx context.Context) error {
	logger.Printf("[ipam-pool-monitor] Starting CNS IPAM Pool Monitor")

	ticker := time.NewTicker(pm.opts.RefreshDelay)
	defer ticker.Stop()

	for {
		// proceed when things happen:
		select {
		case <-ctx.Done(): // calling context has closed, we'll exit.
			return errors.Wrap(ctx.Err(), "pool monitor context closed")
		case <-ticker.C: // attempt to reconcile every tick.
			select {
			case <-pm.started: // this blocks until we have initialized
				// if we have initialized and enter this case, we proceed out of the select and continue to reconcile.
			default:
				// if we have NOT initialized and enter this case, we continue out of this iteration and let the for loop begin again.
				continue
			}
		case nnc := <-pm.nncSource: // received a new NodeNetworkConfig, extract the data from it and re-reconcile.
			pm.spec = nnc.Spec
			scaler := nnc.Status.Scaler

			// Set SubnetName, SubnetAddressSpace and Pod Network ARM ID values to the global subnet, subnetCIDR and subnetARM variables.
			subnet = nnc.Status.NetworkContainers[0].SubnetName
			subnetCIDR = nnc.Status.NetworkContainers[0].SubnetAddressSpace
			subnetARMID = GenerateARMID(&nnc.Status.NetworkContainers[0])

			pm.metastate.batch = scaler.BatchSize
			pm.metastate.max = scaler.MaxIPCount
			pm.metastate.minFreeCount, pm.metastate.maxFreeCount = CalculateMinFreeIPs(scaler), CalculateMaxFreeIPs(scaler)
			pm.once.Do(func() { close(pm.started) }) // close the init channel the first time we receive a NodeNetworkConfig.
		}
		// if control has flowed through the select(s) to this point, we can now reconcile.
		err := pm.reconcile(ctx)
		if err != nil {
			logger.Printf("[ipam-pool-monitor] Reconcile failed with err %v", err)
		}
	}
}

// ipPoolState is the current actual state of the CNS IP pool.
type ipPoolState struct {
	// allocatedToPods are the IPs CNS gives to Pods.
	allocatedToPods int64
	// available are the IPs in state "Available".
	available int64
	// currentAvailableIPs are the current available IPs: allocated - assigned - pendingRelease.
	currentAvailableIPs int64
	// expectedAvailableIPs are the "future" available IPs, if the requested IP count is honored: requested - assigned.
	expectedAvailableIPs int64
	// pendingProgramming are the IPs in state "PendingProgramming".
	pendingProgramming int64
	// pendingRelease are the IPs in state "PendingRelease".
	pendingRelease int64
	// requestedIPs are the IPs CNS has requested that it be allocated by DNC.
	requestedIPs int64
	// totalIPs are all the IPs given to CNS by DNC.
	totalIPs int64
}

func buildIPPoolState(ips map[string]cns.IPConfigurationStatus, spec v1alpha.NodeNetworkConfigSpec) ipPoolState {
	state := ipPoolState{
		totalIPs:     int64(len(ips)),
		requestedIPs: spec.RequestedIPCount,
	}
	for _, v := range ips {
		switch v.GetState() {
		case types.Assigned:
			state.allocatedToPods++
		case types.Available:
			state.available++
		case types.PendingProgramming:
			state.pendingProgramming++
		case types.PendingRelease:
			state.pendingRelease++
		}
	}
	state.currentAvailableIPs = state.totalIPs - state.allocatedToPods - state.pendingRelease
	state.expectedAvailableIPs = state.requestedIPs - state.allocatedToPods
	return state
}

func (pm *Monitor) reconcile(ctx context.Context) error {
	allocatedIPs := pm.httpService.GetPodIPConfigState()
	state := buildIPPoolState(allocatedIPs, pm.spec)
	logger.Printf("ipam-pool-monitor state %+v", state)
	observeIPPoolState(state, pm.metastate, []string{subnet, subnetCIDR, subnetARMID})

	switch {
	// pod count is increasing
	case state.expectedAvailableIPs < pm.metastate.minFreeCount:
		if state.requestedIPs == pm.metastate.max {
			// If we're already at the maxIPCount, don't try to increase
			return nil
		}

		logger.Printf("[ipam-pool-monitor] Increasing pool size...")
		return pm.increasePoolSize(ctx, state)

	// pod count is decreasing
	case state.currentAvailableIPs >= pm.metastate.maxFreeCount:
		logger.Printf("[ipam-pool-monitor] Decreasing pool size...")
		return pm.decreasePoolSize(ctx, state)

	// CRD has reconciled CNS state, and target spec is now the same size as the state
	// free to remove the IPs from the CRD
	case int64(len(pm.spec.IPsNotInUse)) != state.pendingRelease:
		logger.Printf("[ipam-pool-monitor] Removing Pending Release IPs from CRD...")
		return pm.cleanPendingRelease(ctx)

	// no pods scheduled
	case state.allocatedToPods == 0:
		logger.Printf("[ipam-pool-monitor] No pods scheduled")
		return nil
	}

	return nil
}

func (pm *Monitor) increasePoolSize(ctx context.Context, state ipPoolState) error {
	tempNNCSpec := pm.createNNCSpecForCRD()

	// Query the max IP count
	previouslyRequestedIPCount := tempNNCSpec.RequestedIPCount
	batchSize := pm.metastate.batch

	tempNNCSpec.RequestedIPCount += batchSize
	if tempNNCSpec.RequestedIPCount > pm.metastate.max {
		// We don't want to ask for more ips than the max
		logger.Printf("[ipam-pool-monitor] Requested IP count (%d) is over max limit (%d), requesting max limit instead.", tempNNCSpec.RequestedIPCount, pm.metastate.max)
		tempNNCSpec.RequestedIPCount = pm.metastate.max
	}

	// If the requested IP count is same as before, then don't do anything
	if tempNNCSpec.RequestedIPCount == previouslyRequestedIPCount {
		logger.Printf("[ipam-pool-monitor] Previously requested IP count %d is same as updated IP count %d, doing nothing", previouslyRequestedIPCount, tempNNCSpec.RequestedIPCount)
		return nil
	}

	logger.Printf("[ipam-pool-monitor] Increasing pool size, pool %+v, spec %+v", state, tempNNCSpec)

	if _, err := pm.nnccli.UpdateSpec(ctx, &tempNNCSpec); err != nil {
		// caller will retry to update the CRD again
		return err
	}

	logger.Printf("[ipam-pool-monitor] Increasing pool size: UpdateCRDSpec succeeded for spec %+v", tempNNCSpec)
	// start an alloc timer
	metric.StartPoolIncreaseTimer(batchSize)
	// save the updated state to cachedSpec
	pm.spec = tempNNCSpec
	return nil
}

func (pm *Monitor) decreasePoolSize(ctx context.Context, state ipPoolState) error {
	// mark n number of IPs as pending
	var newIpsMarkedAsPending bool
	var pendingIPAddresses map[string]cns.IPConfigurationStatus
	var updatedRequestedIPCount int64

	// Ensure the updated requested IP count is a multiple of the batch size
	previouslyRequestedIPCount := pm.spec.RequestedIPCount
	batchSize := pm.metastate.batch
	modResult := previouslyRequestedIPCount % batchSize

	logger.Printf("[ipam-pool-monitor] Previously RequestedIP Count %d", previouslyRequestedIPCount)
	logger.Printf("[ipam-pool-monitor] Batch size : %d", batchSize)
	logger.Printf("[ipam-pool-monitor] modResult of (previously requested IP count mod batch size) = %d", modResult)

	if modResult != 0 {
		// Example: previouscount = 25, batchsize = 10, 25 - 10 = 15, NOT a multiple of batchsize (10)
		// Don't want that, so make requestedIPCount 20 (25 - (25 % 10)) so that it is a multiple of the batchsize (10)
		updatedRequestedIPCount = previouslyRequestedIPCount - modResult
	} else {
		// Example: previouscount = 30, batchsize = 10, 30 - 10 = 20 which is multiple of batchsize (10) so all good
		updatedRequestedIPCount = previouslyRequestedIPCount - batchSize
	}

	decreaseIPCountBy := previouslyRequestedIPCount - updatedRequestedIPCount

	logger.Printf("[ipam-pool-monitor] updatedRequestedIPCount %d", updatedRequestedIPCount)

	if pm.metastate.notInUseCount == 0 || pm.metastate.notInUseCount < state.pendingRelease {
		logger.Printf("[ipam-pool-monitor] Marking IPs as PendingRelease, ipsToBeReleasedCount %d", decreaseIPCountBy)
		var err error
		if pendingIPAddresses, err = pm.httpService.MarkIPAsPendingRelease(int(decreaseIPCountBy)); err != nil {
			return err
		}

		newIpsMarkedAsPending = true
	}

	tempNNCSpec := pm.createNNCSpecForCRD()

	if newIpsMarkedAsPending {
		// cache the updatingPendingRelease so that we dont re-set new IPs to PendingRelease in case UpdateCRD call fails
		pm.metastate.notInUseCount = int64(len(tempNNCSpec.IPsNotInUse))
	}

	logger.Printf("[ipam-pool-monitor] Releasing IPCount in this batch %d, updatingPendingIpsNotInUse count %d",
		len(pendingIPAddresses), pm.metastate.notInUseCount)

	tempNNCSpec.RequestedIPCount -= int64(len(pendingIPAddresses))
	logger.Printf("[ipam-pool-monitor] Decreasing pool size, pool %+v, spec %+v", state, tempNNCSpec)

	_, err := pm.nnccli.UpdateSpec(ctx, &tempNNCSpec)
	if err != nil {
		// caller will retry to update the CRD again
		return err
	}

	logger.Printf("[ipam-pool-monitor] Decreasing pool size: UpdateCRDSpec succeeded for spec %+v", tempNNCSpec)
	// start a dealloc timer
	metric.StartPoolDecreaseTimer(batchSize)

	// save the updated state to cachedSpec
	pm.spec = tempNNCSpec

	// clear the updatingPendingIpsNotInUse, as we have Updated the CRD
	logger.Printf("[ipam-pool-monitor] cleaning the updatingPendingIpsNotInUse, existing length %d", pm.metastate.notInUseCount)
	pm.metastate.notInUseCount = 0

	return nil
}

// cleanPendingRelease removes IPs from the cache and CRD if the request controller has reconciled
// CNS state and the pending IP release map is empty.
func (pm *Monitor) cleanPendingRelease(ctx context.Context) error {
	tempNNCSpec := pm.createNNCSpecForCRD()

	_, err := pm.nnccli.UpdateSpec(ctx, &tempNNCSpec)
	if err != nil {
		// caller will retry to update the CRD again
		return err
	}

	logger.Printf("[ipam-pool-monitor] cleanPendingRelease: UpdateCRDSpec succeeded for spec %+v", tempNNCSpec)

	// save the updated state to cachedSpec
	pm.spec = tempNNCSpec
	return nil
}

// createNNCSpecForCRD translates CNS's map of IPs to be released and requested IP count into an NNC Spec.
func (pm *Monitor) createNNCSpecForCRD() v1alpha.NodeNetworkConfigSpec {
	var spec v1alpha.NodeNetworkConfigSpec

	// Update the count from cached spec
	spec.RequestedIPCount = pm.spec.RequestedIPCount

	// Get All Pending IPs from CNS and populate it again.
	pendingIPs := pm.httpService.GetPendingReleaseIPConfigs()
	for _, pendingIP := range pendingIPs {
		spec.IPsNotInUse = append(spec.IPsNotInUse, pendingIP.ID)
	}

	return spec
}

// GetStateSnapshot gets a snapshot of the IPAMPoolMonitor struct.
func (pm *Monitor) GetStateSnapshot() cns.IpamPoolMonitorStateSnapshot {
	spec, state := pm.spec, pm.metastate
	return cns.IpamPoolMonitorStateSnapshot{
		MinimumFreeIps:           state.minFreeCount,
		MaximumFreeIps:           state.maxFreeCount,
		UpdatingIpsNotInUseCount: state.notInUseCount,
		CachedNNC: v1alpha.NodeNetworkConfig{
			Spec: spec,
		},
	}
}

// GenerateARMID uses the Subnet ARM ID format to populate the ARM ID with the metadata.
// If either of the metadata attributes are empty, then the ARM ID will be an empty string.
func GenerateARMID(nc *v1alpha.NetworkContainer) string {
	subscription := nc.SubscriptionID
	resourceGroup := nc.ResourceGroupID
	vnetID := nc.VNETID
	subnetID := nc.SubnetID

	if subscription == "" || resourceGroup == "" || vnetID == "" || subnetID == "" {
		return ""
	}
	return fmt.Sprintf(subnetARMIDTemplate, subscription, resourceGroup, vnetID, subnetID)
}

// Update ingests a NodeNetworkConfig, clamping some values to ensure they are legal and then
// pushing it to the Monitor's source channel.
// If the Monitor has been Started but is blocking until it receives an NNC, this will start
// the pool reconcile loop.
// If the Monitor has not been Started, this will block until Start() is called, which will
// immediately read this passed NNC and start the pool reconcile loop.
func (pm *Monitor) Update(nnc *v1alpha.NodeNetworkConfig) error {
	pm.clampScaler(&nnc.Status.Scaler)

	// if the nnc has converged, observe the pool scaling latency (if any).
	allocatedIPs := len(pm.httpService.GetPodIPConfigState()) - len(pm.httpService.GetPendingReleaseIPConfigs())
	if int(nnc.Spec.RequestedIPCount) == allocatedIPs {
		// observe elapsed duration for IP pool scaling
		metric.ObserverPoolScaleLatency()
	}
	pm.nncSource <- *nnc
	return nil
}

// clampScaler makes sure that the values stored in the scaler are sane.
// we usually expect these to be correctly set for us, but we could crash
// without these checks. if they are incorrectly set, there will be some weird
// IP pool behavior for a while until the nnc reconciler corrects the state.
func (pm *Monitor) clampScaler(scaler *v1alpha.Scaler) {
	if scaler.MaxIPCount < 1 {
		scaler.MaxIPCount = pm.opts.MaxIPs
	}
	if scaler.BatchSize < 1 {
		scaler.BatchSize = 1
	}
	if scaler.BatchSize > scaler.MaxIPCount {
		scaler.BatchSize = scaler.MaxIPCount
	}
	if scaler.RequestThresholdPercent < 1 {
		scaler.RequestThresholdPercent = 1
	}
	if scaler.RequestThresholdPercent > 100 { //nolint:gomnd // it's a percent
		scaler.RequestThresholdPercent = 100
	}
	if scaler.ReleaseThresholdPercent < scaler.RequestThresholdPercent+100 {
		scaler.ReleaseThresholdPercent = scaler.RequestThresholdPercent + 100 //nolint:gomnd // it's a percent
	}
}

// CalculateMinFreeIPs calculates the minimum free IP quantity based on the Scaler
// in the passed NodeNetworkConfig.
//nolint:gocritic // ignore hugeparam
func CalculateMinFreeIPs(scaler v1alpha.Scaler) int64 {
	return int64(float64(scaler.BatchSize) * (float64(scaler.RequestThresholdPercent) / 100)) //nolint:gomnd // it's a percent
}

// CalculateMaxFreeIPs calculates the maximum free IP quantity based on the Scaler
// in the passed NodeNetworkConfig.
//nolint:gocritic // ignore hugeparam
func CalculateMaxFreeIPs(scaler v1alpha.Scaler) int64 {
	return int64(float64(scaler.BatchSize) * (float64(scaler.ReleaseThresholdPercent) / 100)) //nolint:gomnd // it's a percent
}
