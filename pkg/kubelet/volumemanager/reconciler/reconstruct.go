/*
Copyright 2022 The Kubernetes Authors.

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

package reconciler

import (
	"context"
	"os"
	"time"

	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/klog/v2"
	"k8s.io/kubernetes/pkg/volume/util/operationexecutor"
)

// readyToUnmount returns true when reconciler can start unmounting volumes.
func (rc *reconciler) readyToUnmount() bool {
	// During kubelet startup, all volumes present on disk are added as uncertain to ASW.
	// Allow unmount only when DSW is fully populated to prevent unmounting volumes that
	// did not reach DSW yet.
	if !rc.populatorHasAddedPods() {
		return false
	}

	// Allow unmount only when ASW device paths were corrected from node.status to prevent
	// calling unmount with a wrong devicePath.
	if len(rc.volumesNeedUpdateFromNodeStatus) != 0 {
		return false
	}
	return true
}

// reconstructVolumes tries to reconstruct the actual state of world by scanning all pods' volume
// directories from the disk. For the volumes that cannot support or fail reconstruction, it will
// put the volumes to volumesFailedReconstruction to be cleaned up later when DesiredStateOfWorld
// is populated.
func (rc *reconciler) reconstructVolumes(logger klog.Logger) {
	// Get volumes information by reading the pod's directory
	podVolumes, err := getVolumesFromPodDir(logger, rc.kubeletPodsDir)
	if err != nil {
		logger.Error(err, "Cannot get volumes from disk, skip sync states for volume reconstruction")
		return
	}
	reconstructedVolumes := make(map[v1.UniqueVolumeName]*globalVolumeInfo)
	reconstructedVolumeNames := []v1.UniqueVolumeName{}
	for _, volume := range podVolumes {
		if rc.actualStateOfWorld.VolumeExistsWithSpecName(volume.podName, volume.volumeSpecName) {
			logger.V(4).Info("Volume exists in actual state, skip cleaning up mounts", "podName", volume.podName, "volumeSpecName", volume.volumeSpecName)
			// There is nothing to reconstruct
			continue
		}
		reconstructedVolume, err := rc.reconstructVolume(volume)
		if err != nil {
			logger.Info("Could not construct volume information", "podName", volume.podName, "volumeSpecName", volume.volumeSpecName, "err", err)
			// We can't reconstruct the volume. Remember to check DSW after it's fully populated and force unmount the volume when it's orphaned.
			rc.volumesFailedReconstruction = append(rc.volumesFailedReconstruction, volume)
			continue
		}
		logger.V(4).Info("Adding reconstructed volume to actual state and node status", "podName", volume.podName, "volumeSpecName", volume.volumeSpecName)
		gvl := &globalVolumeInfo{
			volumeName:        reconstructedVolume.volumeName,
			volumeSpec:        reconstructedVolume.volumeSpec,
			devicePath:        reconstructedVolume.devicePath,
			deviceMounter:     reconstructedVolume.deviceMounter,
			blockVolumeMapper: reconstructedVolume.blockVolumeMapper,
			mounter:           reconstructedVolume.mounter,
		}
		if cachedInfo, ok := reconstructedVolumes[reconstructedVolume.volumeName]; ok {
			gvl = cachedInfo
		}
		gvl.addPodVolume(reconstructedVolume)

		reconstructedVolumeNames = append(reconstructedVolumeNames, reconstructedVolume.volumeName)
		reconstructedVolumes[reconstructedVolume.volumeName] = gvl
	}

	if len(reconstructedVolumes) > 0 {
		// Add the volumes to ASW
		rc.updateStates(logger, reconstructedVolumes)

		// Remember to update devicePath from node.status.volumesAttached
		rc.volumesNeedUpdateFromNodeStatus = reconstructedVolumeNames
	}
	logger.V(2).Info("Volume reconstruction finished")
}

func (rc *reconciler) updateStates(logger klog.Logger, reconstructedVolumes map[v1.UniqueVolumeName]*globalVolumeInfo) {
	for _, gvl := range reconstructedVolumes {
		err := rc.actualStateOfWorld.AddAttachUncertainReconstructedVolume(
			//TODO: the devicePath might not be correct for some volume plugins: see issue #54108
			logger, gvl.volumeName, gvl.volumeSpec, rc.nodeName, gvl.devicePath)
		if err != nil {
			logger.Error(err, "Could not add volume information to actual state of world", "volumeName", gvl.volumeName)
			continue
		}
		var seLinuxMountContext string
		for _, volume := range gvl.podVolumes {
			markVolumeOpts := operationexecutor.MarkVolumeOpts{
				PodName:             volume.podName,
				PodUID:              types.UID(volume.podName),
				VolumeName:          volume.volumeName,
				Mounter:             volume.mounter,
				BlockVolumeMapper:   volume.blockVolumeMapper,
				VolumeGIDVolume:     volume.volumeGIDValue,
				VolumeSpec:          volume.volumeSpec,
				VolumeMountState:    operationexecutor.VolumeMountUncertain,
				SELinuxMountContext: volume.seLinuxMountContext,
			}

			_, err = rc.actualStateOfWorld.CheckAndMarkVolumeAsUncertainViaReconstruction(markVolumeOpts)
			if err != nil {
				logger.Error(err, "Could not add pod to volume information to actual state of world", "pod", klog.KObj(volume.pod))
				continue
			}
			seLinuxMountContext = volume.seLinuxMountContext
			logger.V(2).Info("Volume is marked as uncertain and added into the actual state", "pod", klog.KObj(volume.pod), "podName", volume.podName, "volumeName", volume.volumeName, "seLinuxMountContext", volume.seLinuxMountContext)
		}
		// If the volume has device to mount, we mark its device as uncertain.
		if gvl.deviceMounter != nil || gvl.blockVolumeMapper != nil {
			deviceMountPath, err := getDeviceMountPath(gvl)
			if err != nil {
				logger.Error(err, "Could not find device mount path for volume", "volumeName", gvl.volumeName)
				continue
			}
			err = rc.actualStateOfWorld.MarkDeviceAsUncertain(gvl.volumeName, gvl.devicePath, deviceMountPath, seLinuxMountContext)
			if err != nil {
				logger.Error(err, "Could not mark device is uncertain to actual state of world", "volumeName", gvl.volumeName, "deviceMountPath", deviceMountPath)
				continue
			}
			logger.V(2).Info("Volume is marked device as uncertain and added into the actual state", "volumeName", gvl.volumeName, "deviceMountPath", deviceMountPath)
		}
	}
}

const (
	// orphanCleanupRetryPeriod and orphanCleanupRetryWindow bound the
	// retries of a failed cleanup of a volume that failed reconstruction.
	orphanCleanupRetryPeriod = 10 * time.Second
	orphanCleanupRetryWindow = 5 * time.Minute
)

type orphanCleanupAttempt struct {
	first, last time.Time
}

// cleanOrphanVolumes tries to clean up all volumes that failed reconstruction.
//
// The cleanup runs right after the kubelet starts, possibly before the
// containers of a pod that was deleted meanwhile are killed. Where the
// containers' mounts keep the volume busy (FreeBSD: a container's nullfs
// mount of a subPath holds the kubelet's mount below it, while a Linux mount
// namespace holds copies), the unmount fails once. So a volume whose
// directory is still there is tried again every orphanCleanupRetryPeriod,
// for orphanCleanupRetryWindow.
func (rc *reconciler) cleanOrphanVolumes(logger klog.Logger) {
	if len(rc.volumesFailedReconstruction) == 0 {
		return
	}

	now := time.Now()
	remaining := make([]podVolume, 0)
	for _, volume := range rc.volumesFailedReconstruction {
		key := string(volume.podName) + "/" + volume.volumeSpecName
		if rc.desiredStateOfWorld.VolumeExistsWithSpecName(volume.podName, volume.volumeSpecName) {
			// Some pod needs the volume, don't clean it up and hope that
			// reconcile() calls SetUp and reconstructs the volume in ASW.
			logger.V(4).Info("Volume exists in desired state, skip cleaning up mounts", "podName", volume.podName, "volumeSpecName", volume.volumeSpecName)
			delete(rc.orphanCleanupAttempts, key)
			continue
		}
		attempt, retry := rc.orphanCleanupAttempts[key]
		if retry {
			if _, err := os.Lstat(volume.volumePath); err != nil {
				logger.V(2).Info("Volume that could not be reconstructed is cleaned up", "podName", volume.podName, "volumeSpecName", volume.volumeSpecName)
				delete(rc.orphanCleanupAttempts, key)
				continue
			}
			if now.Sub(attempt.first) > orphanCleanupRetryWindow {
				logger.Info("Giving up cleaning up mounts for volume that could not be reconstructed", "podName", volume.podName, "volumeSpecName", volume.volumeSpecName, "volumePath", volume.volumePath)
				delete(rc.orphanCleanupAttempts, key)
				continue
			}
			if now.Sub(attempt.last) < orphanCleanupRetryPeriod {
				remaining = append(remaining, volume)
				continue
			}
			attempt.last = now
		} else {
			attempt = orphanCleanupAttempt{first: now, last: now}
		}
		logger.Info("Cleaning up mounts for volume that could not be reconstructed", "podName", volume.podName, "volumeSpecName", volume.volumeSpecName)
		rc.cleanupMounts(logger, volume)
		if _, err := os.Lstat(volume.volumePath); err != nil {
			// Nothing left on disk to retry.
			delete(rc.orphanCleanupAttempts, key)
			continue
		}
		rc.orphanCleanupAttempts[key] = attempt
		remaining = append(remaining, volume)
	}

	if len(remaining) == 0 {
		logger.V(2).Info("Orphan volume cleanup finished")
	}
	rc.volumesFailedReconstruction = remaining
}

// updateReconstructedFromNodeStatus tries to file devicePaths of reconstructed volumes from
// node.Status.VolumesAttached. This can be done only after connection to the API
// server is established, i.e. it can't be part of reconstructVolumes().
func (rc *reconciler) updateReconstructedFromNodeStatus(ctx context.Context) {
	logger := klog.FromContext(ctx)
	logger.V(4).Info("Updating reconstructed devicePaths")

	if rc.kubeClient == nil {
		// Skip reconstructing devicePath from node objects if kubelet is in standalone mode.
		// Such kubelet is not expected to mount any attachable volume or Secrets / ConfigMap.
		logger.V(2).Info("Skipped reconstruction of DevicePaths from node.status in standalone mode")
		rc.volumesNeedUpdateFromNodeStatus = nil
		return
	}

	node, fetchErr := rc.kubeClient.CoreV1().Nodes().Get(ctx, string(rc.nodeName), metav1.GetOptions{})
	if fetchErr != nil {
		// This may repeat few times per second until kubelet is able to read its own status for the first time.
		logger.V(4).Info("Failed to get Node status to reconstruct device paths", "err", fetchErr)
		return
	}

	for _, volumeID := range rc.volumesNeedUpdateFromNodeStatus {
		attachable := false
		for _, attachedVolume := range node.Status.VolumesAttached {
			if volumeID != attachedVolume.Name {
				continue
			}
			rc.actualStateOfWorld.UpdateReconstructedDevicePath(volumeID, attachedVolume.DevicePath)
			attachable = true
			logger.V(4).Info("Updated devicePath from node status for volume", "volumeName", attachedVolume.Name, "path", attachedVolume.DevicePath)
		}
		rc.actualStateOfWorld.UpdateReconstructedVolumeAttachability(volumeID, attachable)
	}

	logger.V(2).Info("DevicePaths of reconstructed volumes updated")
	rc.volumesNeedUpdateFromNodeStatus = nil
}
