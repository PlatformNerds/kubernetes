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

// containerManagerImpl implements container manager on FreeBSD.
// Only GetNodeAllocatableReservation() and GetCapacity() are implemented now.

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
	clientset "k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/record"
	internalapi "k8s.io/cri-api/pkg/apis"
	pluginwatcherapi "k8s.io/kubelet/pkg/apis/pluginregistration/v1"
	podresourcesapi "k8s.io/kubelet/pkg/apis/podresources/v1"
	"k8s.io/kubernetes/pkg/kubelet/cadvisor"
	"k8s.io/kubernetes/pkg/kubelet/cm/admission"
	"k8s.io/kubernetes/pkg/kubelet/cm/cpumanager"
	"k8s.io/kubernetes/pkg/kubelet/cm/devicemanager"
	"k8s.io/kubernetes/pkg/kubelet/cm/memorymanager"
	"k8s.io/kubernetes/pkg/kubelet/cm/resourceupdates"
	"k8s.io/kubernetes/pkg/kubelet/cm/topologymanager"
	"k8s.io/kubernetes/pkg/kubelet/config"
	kubecontainer "k8s.io/kubernetes/pkg/kubelet/container"
	"k8s.io/kubernetes/pkg/kubelet/lifecycle"
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
}

type noopResourceAllocator struct{}

func (ra *noopResourceAllocator) Admit(attrs *lifecycle.PodAdmitAttributes) lifecycle.PodAdmitResult {
	return admission.GetPodAdmitResult(nil)
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

	// Starts device manager.
	if err := cm.deviceManager.Start(klog.FromContext(ctx), devicemanager.ActivePodsFunc(activePods), sourcesReady, containerMap, containerRunningSet); err != nil {
		return err
	}

	return nil
}

func (cm *containerManagerImpl) GetPluginRegistrationHandlers() map[string]cache.PluginHandler {
	return map[string]cache.PluginHandler{
		pluginwatcherapi.DevicePlugin: cm.deviceManager.GetWatcherHandler(),
	}
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

	cm.topologyManager = topologymanager.NewFakeManager()

	logger.Info("Creating device plugin manager")
	cm.deviceManager, err = devicemanager.NewManagerImpl(nil, cm.topologyManager)
	if err != nil {
		return nil, err
	}
	cm.topologyManager.AddHintProvider(logger, cm.deviceManager)

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
	return opts, nil
}

func (cm *containerManagerImpl) UpdatePluginResources(node *schedulerframework.NodeInfo, attrs *lifecycle.PodAdmitAttributes) error {
	return cm.deviceManager.UpdatePluginResources(node, attrs)
}

func (cm *containerManagerImpl) InternalContainerLifecycle() InternalContainerLifecycle {
	logger := klog.TODO()
	return &internalContainerLifecycleImpl{cpumanager.NewFakeManager(logger), memorymanager.NewFakeManager(logger), topologymanager.NewFakeManager()}
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
	return &noopResourceAllocator{}
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

func (cm *containerManagerImpl) GetDynamicResources(pod *v1.Pod, container *v1.Container) []*podresourcesapi.DynamicResource {
	return nil
}

func (cm *containerManagerImpl) UpdateAllocatedResourcesStatus(pod *v1.Pod, status *v1.PodStatus) {
	cm.deviceManager.UpdateAllocatedResourcesStatus(pod, status)
}

func (cm *containerManagerImpl) Updates() <-chan resourceupdates.Update {
	return cm.deviceManager.Updates()
}

func (cm *containerManagerImpl) PrepareDynamicResources(ctx context.Context, pod *v1.Pod) error {
	return nil
}

func (cm *containerManagerImpl) UnprepareDynamicResources(ctx context.Context, pod *v1.Pod) error {
	return nil
}

func (cm *containerManagerImpl) PodMightNeedToUnprepareResources(UID types.UID) bool {
	return false
}
