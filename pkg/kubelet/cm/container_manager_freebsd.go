//go:build freebsd

/*
Copyright 2015 The Kubernetes Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

// containerManagerImpl implements container manager on FreeBSD: capacity and
// allocatable, device plugins and Dynamic Resource Allocation. There are no
// cgroups: the runtime enforces limits with rctl(8).

package cm

import (
	"context"
	"fmt"
	"math"
	"sync"

	"k8s.io/klog/v2"
	"k8s.io/mount-utils"

	v1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apiserver/pkg/server/healthz"
	utilfeature "k8s.io/apiserver/pkg/util/feature"
	clientset "k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/record"
	internalapi "k8s.io/cri-api/pkg/apis"
	pluginwatcherapi "k8s.io/kubelet/pkg/apis/pluginregistration/v1"
	podresourcesapi "k8s.io/kubelet/pkg/apis/podresources/v1"
	kubefeatures "k8s.io/kubernetes/pkg/features"
	"k8s.io/kubernetes/pkg/kubelet/cadvisor"
	"k8s.io/kubernetes/pkg/kubelet/cm/cpumanager"
	"k8s.io/kubernetes/pkg/kubelet/cm/devicemanager"
	"k8s.io/kubernetes/pkg/kubelet/cm/dra"
	"k8s.io/kubernetes/pkg/kubelet/cm/memorymanager"
	"k8s.io/kubernetes/pkg/kubelet/cm/resourceupdates"
	"k8s.io/kubernetes/pkg/kubelet/cm/topologymanager"
	"k8s.io/kubernetes/pkg/kubelet/config"
	kubecontainer "k8s.io/kubernetes/pkg/kubelet/container"
	"k8s.io/kubernetes/pkg/kubelet/lifecycle"
	"k8s.io/kubernetes/pkg/kubelet/metrics"
	"k8s.io/kubernetes/pkg/kubelet/pluginmanager/cache"
	"k8s.io/kubernetes/pkg/kubelet/status"
	schedulerframework "k8s.io/kubernetes/pkg/scheduler/framework"
)

type containerManagerImpl struct {
	// Capacity of this node.
	capacity v1.ResourceList
	// Interface for cadvisor.
	cadvisorInterface cadvisor.Interface
	// Config of this node.
	nodeConfig NodeConfig
	// Interface for exporting and allocating devices reported by device plugins.
	deviceManager devicemanager.Manager
	// Interface for Topology resource co-ordination
	topologyManager topologymanager.Manager
	// Dynamic Resource Allocation: prepares ResourceClaims through the DRA
	// drivers' kubelet plugins and hands their CDI devices to the runtime.
	// nil when the DynamicResourceAllocation feature is off.
	draManager *dra.Manager
	// Updates of the device manager and the DRA manager, merged.
	resourceUpdates chan resourceupdates.Update
}

func (cm *containerManagerImpl) Start(ctx context.Context, node *v1.Node,
	activePods ActivePodsFunc,
	getNode GetNodeFunc,
	sourcesReady config.SourcesReady,
	podStatusProvider status.PodStatusProvider,
	runtimeService internalapi.RuntimeService,
	localStorageCapacityIsolation bool) error {
	klog.V(2).InfoS("Starting FreeBSD container manager")

	if localStorageCapacityIsolation {
		rootfs, err := cm.cadvisorInterface.RootFsInfo()
		if err != nil {
			return fmt.Errorf("failed to get rootfs info: %v", err)
		}
		for rName, rCap := range cadvisor.EphemeralStorageCapacityFromFsInfo(rootfs) {
			cm.capacity[rName] = rCap
		}
	}

	containerMap, containerRunningSet := buildContainerMapAndRunningSetFromRuntime(ctx, runtimeService)

	if cm.draManager != nil {
		if err := cm.draManager.Start(ctx, dra.ActivePodsFunc(activePods), dra.GetNodeFunc(getNode), sourcesReady); err != nil {
			return fmt.Errorf("start dra manager error: %w", err)
		}
	}

	// Starts device manager.
	if err := cm.deviceManager.Start(klog.FromContext(ctx), devicemanager.ActivePodsFunc(activePods), sourcesReady, containerMap, containerRunningSet); err != nil {
		return err
	}

	return nil
}

func (cm *containerManagerImpl) GetPluginRegistrationHandlers() map[string]cache.PluginHandler {
	res := map[string]cache.PluginHandler{
		pluginwatcherapi.DevicePlugin: cm.deviceManager.GetWatcherHandler(),
	}
	if cm.draManager != nil {
		res[pluginwatcherapi.DRAPlugin] = cm.draManager.GetWatcherHandler()
	}
	return res
}

// NewContainerManager creates FreeBSD container manager.
func NewContainerManager(ctx context.Context, mountUtil mount.Interface, cadvisorInterface cadvisor.Interface, nodeConfig NodeConfig, failSwapOn bool, recorder record.EventRecorder, kubeClient clientset.Interface) (ContainerManager, error) {
	logger := klog.FromContext(ctx)

	// It is safe to invoke `MachineInfo` on cAdvisor before logically initializing cAdvisor here because
	// machine info is computed and cached once as part of cAdvisor object creation.
	// But `RootFsInfo` and `ImagesFsInfo` are not available at this moment so they will be called later during manager starts
	machineInfo, err := cadvisorInterface.MachineInfo()
	if err != nil {
		return nil, err
	}
	capacity := cadvisor.CapacityFromMachineInfo(machineInfo)

	cm := &containerManagerImpl{
		capacity:          capacity,
		nodeConfig:        nodeConfig,
		cadvisorInterface: cadvisorInterface,
	}

	// The "none" policy: no NUMA alignment, but its admit handler has the
	// device manager allocate devices to the pod's containers (the fake
	// manager admitted without, so device plugin devices never reached a
	// container).
	cm.topologyManager, err = topologymanager.NewManager(nil, topologymanager.PolicyNone, "", nil)
	if err != nil {
		return nil, err
	}

	logger.Info("Creating device plugin manager")
	cm.deviceManager, err = devicemanager.NewManagerImpl(nil, cm.topologyManager)
	if err != nil {
		return nil, err
	}
	cm.topologyManager.AddHintProvider(logger, cm.deviceManager)

	if utilfeature.DefaultFeatureGate.Enabled(kubefeatures.DynamicResourceAllocation) {
		logger.Info("Creating Dynamic Resource Allocation (DRA) manager")
		cm.draManager, err = dra.NewManager(logger, kubeClient, nodeConfig.KubeletRootDir)
		if err != nil {
			return nil, err
		}
		metrics.RegisterCollectors(cm.draManager.NewMetricsCollector())
	}

	// One channel for the kubelet's sync loop, fed by the device manager
	// and (with ResourceHealthStatus) the DRA manager, as on Linux.
	cm.resourceUpdates = make(chan resourceupdates.Update, 10)
	sources := map[string]<-chan resourceupdates.Update{"deviceManager": cm.deviceManager.Updates()}
	if cm.draManager != nil && utilfeature.DefaultFeatureGate.Enabled(kubefeatures.ResourceHealthStatus) {
		sources["draManager"] = cm.draManager.Updates()
	}
	var wg sync.WaitGroup
	for name, ch := range sources {
		wg.Add(1)
		go func(name string, c <-chan resourceupdates.Update) {
			defer wg.Done()
			for v := range c {
				logger.V(4).Info("Container Manager: forwarding resource update", "source", name, "pods", v.PodUIDs)
				cm.resourceUpdates <- v
			}
		}(name, ch)
	}
	go func() {
		wg.Wait()
		close(cm.resourceUpdates)
	}()

	return cm, nil
}

func (cm *containerManagerImpl) SystemCgroupsLimit() v1.ResourceList {
	return v1.ResourceList{}
}

func (cm *containerManagerImpl) GetNodeConfig() NodeConfig {
	return NodeConfig{}
}

func (cm *containerManagerImpl) GetMountedSubsystems() *CgroupSubsystems {
	return &CgroupSubsystems{}
}

func (cm *containerManagerImpl) GetQOSContainersInfo() QOSContainersInfo {
	return QOSContainersInfo{}
}

func (cm *containerManagerImpl) UpdateQOSCgroups(logger klog.Logger) error {
	return nil
}

func (cm *containerManagerImpl) Status() Status {
	return Status{}
}

func (cm *containerManagerImpl) GetNodeAllocatableReservation() v1.ResourceList {
	evictionReservation := hardEvictionReservation(cm.nodeConfig.HardEvictionThresholds, cm.capacity)
	result := make(v1.ResourceList)
	for k := range cm.capacity {
		value := resource.NewQuantity(0, resource.DecimalSI)
		if cm.nodeConfig.SystemReserved != nil {
			value.Add(cm.nodeConfig.SystemReserved[k])
		}
		if cm.nodeConfig.KubeReserved != nil {
			value.Add(cm.nodeConfig.KubeReserved[k])
		}
		if evictionReservation != nil {
			value.Add(evictionReservation[k])
		}
		if !value.IsZero() {
			result[k] = *value
		}
	}
	return result
}

func (cm *containerManagerImpl) GetCapacity(localStorageCapacityIsolation bool) v1.ResourceList {
	return cm.capacity
}

func (cm *containerManagerImpl) GetPluginRegistrationHandler() cache.PluginHandler {
	return cm.deviceManager.GetWatcherHandler()
}

func (cm *containerManagerImpl) GetDevicePluginResourceCapacity() (v1.ResourceList, v1.ResourceList, []string) {
	return cm.deviceManager.GetCapacity()
}

func (cm *containerManagerImpl) NewPodContainerManager() PodContainerManager {
	return &podContainerManagerFreeBSD{}
}

// podContainerManagerFreeBSD: FreeBSD has no pod cgroup. Pod-level limits are
// rctl rules on the pod jail (the parent of the container jails), set by the
// runtime from the sandbox config at creation and from
// UpdatePodSandboxResources during an in-place resize.
//
// The kubelet compares GetPodCgroupConfig with the pod's desired config to
// decide whether, and in which order, to update the pod-level limits around
// the container updates. So GetPodCgroupConfig reports what was last applied
// to the pod jail (recorded at sandbox creation and by SetPodCgroupConfig,
// which the kubelet calls once the runtime accepted the update). Unknown
// values (e.g. after a kubelet restart) are reported as unlimited, so the
// kubelet sends the pod's limits again, which is idempotent. The resize code
// dereferences these values, so they are never nil.
type podContainerManagerFreeBSD struct {
	podContainerManagerStub
}

// podLevelApplied maps a pod UID to the pod-level config last applied to its
// pod jail.
var podLevelApplied sync.Map

// RecordPodLevelConfig records the pod-level config the runtime was given
// for a pod's sandbox (nil: none).
func RecordPodLevelConfig(uid types.UID, rc *ResourceConfig) {
	if rc == nil {
		podLevelApplied.Delete(uid)
		return
	}
	c := *rc
	podLevelApplied.Store(uid, &c)
}

func appliedPodLevelConfig(uid types.UID) ResourceConfig {
	if v, ok := podLevelApplied.Load(uid); ok {
		return *v.(*ResourceConfig)
	}
	return ResourceConfig{}
}

func (m *podContainerManagerFreeBSD) GetPodCgroupConfig(pod *v1.Pod, resourceName v1.ResourceName) (*ResourceConfig, error) {
	rc := appliedPodLevelConfig(pod.UID)
	switch resourceName {
	case v1.ResourceMemory:
		memory := int64(math.MaxInt64)
		if rc.Memory != nil {
			memory = *rc.Memory
		}
		return &ResourceConfig{Memory: &memory}, nil
	case v1.ResourceCPU:
		quota, period, shares := int64(-1), uint64(QuotaPeriod), uint64(MinShares)
		if rc.CPUQuota != nil {
			quota = *rc.CPUQuota
		}
		if rc.CPUPeriod != nil {
			period = *rc.CPUPeriod
		}
		if rc.CPUShares != nil {
			shares = *rc.CPUShares
		}
		return &ResourceConfig{CPUQuota: &quota, CPUPeriod: &period, CPUShares: &shares}, nil
	}
	return nil, fmt.Errorf("unsupported pod resource %q", resourceName)
}

// SetPodCgroupConfig records the pod-level values the runtime accepted
// (UpdatePodSandboxResources, called just before); there is no cgroup to write.
func (m *podContainerManagerFreeBSD) SetPodCgroupConfig(_ klog.Logger, pod *v1.Pod, update *ResourceConfig) error {
	if update == nil {
		return nil
	}
	rc := appliedPodLevelConfig(pod.UID)
	if update.Memory != nil {
		rc.Memory = update.Memory
	}
	if update.CPUQuota != nil {
		rc.CPUQuota = update.CPUQuota
	}
	if update.CPUPeriod != nil {
		rc.CPUPeriod = update.CPUPeriod
	}
	if update.CPUShares != nil {
		rc.CPUShares = update.CPUShares
	}
	RecordPodLevelConfig(pod.UID, &rc)
	return nil
}

func (cm *containerManagerImpl) PodHasExclusiveCPUs(pod *v1.Pod) bool {
	return false
}

func (cm *containerManagerImpl) ContainerHasExclusiveCPUs(pod *v1.Pod, container *v1.Container) bool {
	return false
}

func (cm *containerManagerImpl) GetHealthCheckers() []healthz.HealthChecker {
	return []healthz.HealthChecker{cm.deviceManager.GetHealthChecker()}
}

func (cm *containerManagerImpl) GetResources(ctx context.Context, pod *v1.Pod, container *v1.Container) (*kubecontainer.RunContainerOptions, error) {
	opts := &kubecontainer.RunContainerOptions{}
	if cm.draManager != nil {
		resOpts, err := cm.draManager.GetResources(pod, container)
		if err != nil {
			return nil, err
		}
		klog.FromContext(ctx).V(5).Info("Determined CDI devices for pod", "pod", klog.KObj(pod), "cdiDevices", resOpts.CDIDevices)
		opts.CDIDevices = append(opts.CDIDevices, resOpts.CDIDevices...)
	}
	// Allocate should already be called during predicateAdmitHandler.Admit(),
	// just try to fetch device runtime information from cached state here
	devOpts, err := cm.deviceManager.GetDeviceRunContainerOptions(ctx, pod, container)
	if err != nil {
		return nil, err
	} else if devOpts == nil {
		return opts, nil
	}
	opts.Devices = append(opts.Devices, devOpts.Devices...)
	opts.Mounts = append(opts.Mounts, devOpts.Mounts...)
	opts.Envs = append(opts.Envs, devOpts.Envs...)
	opts.Annotations = append(opts.Annotations, devOpts.Annotations...)
	opts.CDIDevices = append(opts.CDIDevices, devOpts.CDIDevices...)
	return opts, nil
}

func (cm *containerManagerImpl) UpdatePluginResources(node *schedulerframework.NodeInfo, attrs *lifecycle.PodAdmitAttributes) error {
	return cm.deviceManager.UpdatePluginResources(node, attrs)
}

func (cm *containerManagerImpl) InternalContainerLifecycle() InternalContainerLifecycle {
	logger := klog.TODO()
	return &internalContainerLifecycleImpl{cpumanager.NewFakeManager(logger), memorymanager.NewFakeManager(logger), cm.topologyManager}
}

func (cm *containerManagerImpl) GetPodCgroupRoot() string {
	return ""
}

func (cm *containerManagerImpl) GetDevices(podUID, containerName string) []*podresourcesapi.ContainerDevices {
	return containerDevicesFromResourceDeviceInstances(cm.deviceManager.GetDevices(podUID, containerName))
}

func (cm *containerManagerImpl) GetAllocatableDevices() []*podresourcesapi.ContainerDevices {
	return nil
}

func (cm *containerManagerImpl) ShouldResetExtendedResourceCapacity() bool {
	return cm.deviceManager.ShouldResetExtendedResourceCapacity()
}

func (cm *containerManagerImpl) GetAllocateResourcesPodAdmitHandler() lifecycle.PodAdmitHandler {
	return cm.topologyManager
}

func (cm *containerManagerImpl) UpdateAllocatedDevices() {
	return
}

func (cm *containerManagerImpl) GetCPUs(_, _ string) []int64 {
	return nil
}

func (cm *containerManagerImpl) GetAllocatableCPUs() []int64 {
	return nil
}

func (cm *containerManagerImpl) GetMemory(_, _ string) []*podresourcesapi.ContainerMemory {
	return nil
}

func (cm *containerManagerImpl) GetAllocatableMemory() []*podresourcesapi.ContainerMemory {
	return nil
}

func (cm *containerManagerImpl) GetNodeAllocatableAbsolute() v1.ResourceList {
	return nil
}

// GetDynamicResources reports a container's DRA devices to the pod resources
// API, as on Linux.
func (cm *containerManagerImpl) GetDynamicResources(pod *v1.Pod, container *v1.Container) []*podresourcesapi.DynamicResource {
	if cm.draManager == nil {
		return []*podresourcesapi.DynamicResource{}
	}
	containerClaimInfos, err := cm.draManager.GetContainerClaimInfos(pod, container)
	if err != nil {
		klog.TODO().Error(err, "Unable to get container claim info state")
		return []*podresourcesapi.DynamicResource{}
	}
	var containerDynamicResources []*podresourcesapi.DynamicResource
	for _, containerClaimInfo := range containerClaimInfos {
		var claimResources []*podresourcesapi.ClaimResource
		for driverName, driverState := range containerClaimInfo.DriverState {
			var cdiDevices []*podresourcesapi.CDIDevice
			for _, device := range driverState.Devices {
				for _, cdiDeviceID := range device.CDIDeviceIDs {
					cdiDevices = append(cdiDevices, &podresourcesapi.CDIDevice{Name: cdiDeviceID})
				}
				claimResources = append(claimResources, &podresourcesapi.ClaimResource{
					CdiDevices: cdiDevices,
					DriverName: driverName,
					PoolName:   device.PoolName,
					DeviceName: device.DeviceName,
					ShareId:    (*string)(device.ShareID),
				})
			}
		}
		containerDynamicResources = append(containerDynamicResources, &podresourcesapi.DynamicResource{
			ClaimName:      containerClaimInfo.ClaimName,
			ClaimNamespace: containerClaimInfo.Namespace,
			ClaimResources: claimResources,
		})
	}
	return containerDynamicResources
}

func (cm *containerManagerImpl) UpdateAllocatedResourcesStatus(pod *v1.Pod, status *v1.PodStatus) {
	cm.deviceManager.UpdateAllocatedResourcesStatus(pod, status)
	if cm.draManager != nil && utilfeature.DefaultFeatureGate.Enabled(kubefeatures.ResourceHealthStatus) {
		cm.draManager.UpdateAllocatedResourcesStatus(pod, status)
	}
}

func (cm *containerManagerImpl) Updates() <-chan resourceupdates.Update {
	return cm.resourceUpdates
}

func (cm *containerManagerImpl) PrepareDynamicResources(ctx context.Context, pod *v1.Pod) error {
	if cm.draManager == nil {
		return nil
	}
	return cm.draManager.PrepareResources(ctx, pod)
}

func (cm *containerManagerImpl) UnprepareDynamicResources(ctx context.Context, pod *v1.Pod) error {
	if cm.draManager == nil {
		return nil
	}
	return cm.draManager.UnprepareResources(ctx, pod)
}

func (cm *containerManagerImpl) PodMightNeedToUnprepareResources(UID types.UID) bool {
	if cm.draManager == nil {
		return false
	}
	return cm.draManager.PodMightNeedToUnprepareResources(UID)
}

// FreeBSDPodContainerManagerForTest gives tests in other packages the FreeBSD
// pod container manager.
type FreeBSDPodContainerManagerForTest = podContainerManagerFreeBSD
