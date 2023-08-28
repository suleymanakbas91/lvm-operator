/*
Copyright © 2023 Red Hat, Inc.

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

package vgmanager

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"strings"

	lvmv1alpha1 "github.com/openshift/lvm-operator/api/v1alpha1"
	"github.com/openshift/lvm-operator/pkg/internal"
	"sigs.k8s.io/controller-runtime/pkg/log"
)

// addDevicesToVG creates or extends a volume group using the provided devices.
func (r *VGReconciler) addDevicesToVG(ctx context.Context, vgs []VolumeGroup, vgName string, devices []internal.BlockDevice) error {
	logger := log.FromContext(ctx)

	if len(devices) < 1 {
		return fmt.Errorf("can't create vg %q with 0 devices", vgName)
	}

	// check if volume group is already present
	vgFound := false
	for _, vg := range vgs {
		if vg.Name == vgName {
			vgFound = true
		}
	}

	// TODO: Check if we can use functions from lvm.go here
	var cmd string
	if vgFound {
		logger.Info("extending an existing volume group", "VGName", vgName)
		cmd = "/usr/sbin/vgextend"
	} else {
		logger.Info("creating a new volume group", "VGName", vgName)
		cmd = "/usr/sbin/vgcreate"
	}

	args := []string{vgName}
	for _, device := range devices {
		if device.DevicePath != "" {
			args = append(args, device.DevicePath)
		} else {
			args = append(args, device.KName)
		}
	}

	_, err := r.executor.ExecuteCommandWithOutputAsHost(cmd, args...)
	if err != nil {
		return fmt.Errorf("failed to create or extend volume group %q using command '%s': %v", vgName, fmt.Sprintf("%s %s", cmd, strings.Join(args, " ")), err)
	}

	return nil
}

// getAvailableDevicesForVG determines the available devices that can be used to create a volume group.
func (r *VGReconciler) getAvailableDevicesForVG(ctx context.Context, blockDevices []internal.BlockDevice, vgs []VolumeGroup, volumeGroup *lvmv1alpha1.LVMVolumeGroup) ([]internal.BlockDevice, error) {
	// filter devices based on DeviceSelector.Paths if specified
	matchingDevices, err := r.filterMatchingDevices(ctx, blockDevices, vgs, volumeGroup)
	if err != nil {
		return nil, fmt.Errorf("failed to filter matching devices for volume group %s: %w", volumeGroup.GetName(), err)
	}

	return r.filterAvailableDevices(ctx, matchingDevices), nil
}

// filterAvailableDevices returns:
// availableDevices: the list of blockdevices considered available
func (r *VGReconciler) filterAvailableDevices(ctx context.Context, blockDevices []internal.BlockDevice) []internal.BlockDevice {
	logger := log.FromContext(ctx)

	var availableDevices []internal.BlockDevice
	// using a label so `continue DeviceLoop` can be used to skip devices
DeviceLoop:
	for _, blockDevice := range blockDevices {
		// check for partitions recursively
		if blockDevice.HasChildren() {
			childAvailableDevices := r.filterAvailableDevices(ctx, blockDevice.Children)
			availableDevices = append(availableDevices, childAvailableDevices...)
		}

		logger = logger.WithValues("Device.Name", blockDevice.Name)
		for name, filter := range FilterMap {
			logger := logger.WithValues("filter.Name", name)
			valid, err := filter(blockDevice, r.executor)
			if err != nil {
				logger.Error(err, "filter error")
				continue DeviceLoop
			} else if !valid {
				logger.Info("does not match filter")
				continue DeviceLoop
			}
		}
		availableDevices = append(availableDevices, blockDevice)
	}
	return availableDevices
}

// filterMatchingDevices filters devices based on DeviceSelector.Paths if specified.
func (r *VGReconciler) filterMatchingDevices(ctx context.Context, blockDevices []internal.BlockDevice, vgs []VolumeGroup, volumeGroup *lvmv1alpha1.LVMVolumeGroup) ([]internal.BlockDevice, error) {
	logger := log.FromContext(ctx)

	var filteredBlockDevices []internal.BlockDevice
	devicesAlreadyInVG := false

	if volumeGroup.Spec.DeviceSelector != nil {

		if err := checkDuplicateDeviceSelectorPaths(volumeGroup.Spec.DeviceSelector); err != nil {
			return nil, fmt.Errorf("unable to validate device selector paths: %v", err)
		}

		// If Paths is specified, treat it as required paths
		for _, path := range volumeGroup.Spec.DeviceSelector.Paths {
			blockDevice, err := getValidDevice(path, blockDevices, vgs, volumeGroup)
			if err != nil {
				// An error for required devices is critical
				return nil, fmt.Errorf("unable to validate device %s: %v", path, err)
			}

			// Check if we should skip this device
			if blockDevice.DevicePath == "" {
				logger.Info(fmt.Sprintf("skipping required device that is already part of volume group %s: %s", volumeGroup.Name, path))
				devicesAlreadyInVG = true
				continue
			}

			filteredBlockDevices = append(filteredBlockDevices, blockDevice)
		}

		// Check for any optional paths
		if len(volumeGroup.Spec.DeviceSelector.OptionalPaths) > 0 {
			for _, path := range volumeGroup.Spec.DeviceSelector.OptionalPaths {
				blockDevice, err := getValidDevice(path, blockDevices, vgs, volumeGroup)

				// Check if we should skip this device
				if err != nil {
					logger.Info(fmt.Sprintf("skipping optional device path: %v", err))
					continue
				}

				// Check if we should skip this device
				if blockDevice.DevicePath == "" {
					logger.Info(fmt.Sprintf("skipping optional device path that is already part of volume group %s: %s", volumeGroup.Name, path))
					devicesAlreadyInVG = true
					continue
				}

				filteredBlockDevices = append(filteredBlockDevices, blockDevice)
			}

			// At least 1 of the optional paths are required if:
			//   - OptionalPaths was specified AND
			//   - There were no required paths
			//   - Devices were not already part of the volume group (meaning this was run after vg creation)
			// This guarantees at least 1 device could be found between optionalPaths and paths
			// if len(filteredBlockDevices) == 0 && !devicesAlreadyInVG {
			if len(filteredBlockDevices) == 0 && !devicesAlreadyInVG {
				return nil, errors.New("at least 1 valid device is required if DeviceSelector paths or optionalPaths are specified")
			}
		}

		return filteredBlockDevices, nil
	}

	// return all available block devices if none is specified in the CR
	return blockDevices, nil
}

func isDeviceAlreadyPartOfVG(vgs []VolumeGroup, diskName string, volumeGroup *lvmv1alpha1.LVMVolumeGroup) bool {
	for _, vg := range vgs {
		if vg.Name == volumeGroup.Name {
			for _, pv := range vg.PVs {
				if pv == diskName {
					return true
				}
			}
		}
	}

	return false
}

func hasExactDisk(blockDevices []internal.BlockDevice, deviceName string) (internal.BlockDevice, bool) {
	for _, blockDevice := range blockDevices {
		if blockDevice.KName == deviceName {
			return blockDevice, true
		}
		if blockDevice.HasChildren() {
			if device, ok := hasExactDisk(blockDevice.Children, deviceName); ok {
				return device, true
			}
		}
	}
	return internal.BlockDevice{}, false
}

func checkDuplicateDeviceSelectorPaths(selector *lvmv1alpha1.DeviceSelector) error {
	uniquePaths := make(map[string]bool)
	duplicatePaths := make(map[string]bool)

	// Check for duplicate required paths
	for _, path := range selector.Paths {
		if _, exists := uniquePaths[path]; exists {
			duplicatePaths[path] = true
			continue
		}

		uniquePaths[path] = true
	}

	// Check for duplicate optional paths
	for _, path := range selector.OptionalPaths {
		if _, exists := uniquePaths[path]; exists {
			duplicatePaths[path] = true
			continue
		}

		uniquePaths[path] = true
	}

	// Report any duplicate paths
	if len(duplicatePaths) > 0 {
		keys := make([]string, 0, len(duplicatePaths))
		for k := range duplicatePaths {
			keys = append(keys, k)
		}

		return fmt.Errorf("duplicate device paths found: %v", keys)
	}

	return nil
}

// getValidDevice will do various checks on a device path to make sure it is a valid device
//
//	An error will be returned if the device is invalid
//	No error and an empty BlockDevice object will be returned if this device should be skipped (ex: duplicate device)
func getValidDevice(devicePath string, blockDevices []internal.BlockDevice, vgs []VolumeGroup, volumeGroup *lvmv1alpha1.LVMVolumeGroup) (internal.BlockDevice, error) {
	// Make sure the symlink exists
	diskName, err := filepath.EvalSymlinks(devicePath)
	if err != nil {
		return internal.BlockDevice{}, fmt.Errorf("unable to find symlink for disk path %s: %v", devicePath, err)
	}

	// Make sure this isn't a duplicate in the VG
	if isDeviceAlreadyPartOfVG(vgs, diskName, volumeGroup) {
		return internal.BlockDevice{}, nil // No error, we just don't want a duplicate
	}

	// Make sure the block device exists
	blockDevice, ok := hasExactDisk(blockDevices, diskName)
	if !ok {
		return internal.BlockDevice{}, fmt.Errorf("can not find device name %s in the available block devices", devicePath)
	}

	blockDevice.DevicePath = devicePath
	return blockDevice, nil
}
