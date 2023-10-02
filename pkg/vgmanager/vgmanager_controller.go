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
	"fmt"
	"strconv"
	"time"

	"github.com/google/go-cmp/cmp"
	lvmv1alpha1 "github.com/openshift/lvm-operator/api/v1alpha1"
	"github.com/openshift/lvm-operator/controllers"
	"github.com/openshift/lvm-operator/pkg/dmsetup"
	"github.com/openshift/lvm-operator/pkg/filter"
	"github.com/openshift/lvm-operator/pkg/lsblk"
	"github.com/openshift/lvm-operator/pkg/lvm"
	"github.com/openshift/lvm-operator/pkg/lvmd"
	"github.com/openshift/lvm-operator/pkg/wipefs"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/tools/record"
	corev1helper "k8s.io/component-helpers/scheduling/corev1"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
)

const (
	ControllerName            = "vg-manager"
	reconcileInterval         = 15 * time.Second
	metadataWarningPercentage = 95

	// NodeCleanupFinalizer should be set on a LVMVolumeGroup for every Node matching that LVMVolumeGroup.
	// When the LVMVolumeGroup gets deleted, this finalizer will stay on the VolumeGroup until the vgmanager instance
	// on that node has fulfilled all cleanup routines for the vg (remove lvs, vgs, pvs and lvmd conf entry).
	NodeCleanupFinalizer = "cleanup.vgmanager.node.topolvm.io"
)

type EventReasonInfo string
type EventReasonError string

const EventReasonErrorNoAvailableDevicesForVG EventReasonError = "NoAvailableDevicesForVG"
const EventReasonErrorInconsistentLVs EventReasonError = "InconsistentLVs"
const EventReasonErrorVGCreateOrExtendFailed EventReasonError = "VGCreateOrExtendFailed"
const EventReasonErrorThinPoolCreateOrExtendFailed EventReasonError = "ThinPoolCreateOrExtendFailed"
const EventReasonLVMDConfigMissing EventReasonInfo = "LVMDConfigMissing"
const EventReasonLVMDConfigUpdated EventReasonInfo = "LVMDConfigUpdated"
const EventReasonLVMDConfigDeleted EventReasonInfo = "LVMDConfigDeleted"
const EventReasonVolumeGroupReady EventReasonInfo = "VolumeGroupReady"

var (
	reconcileAgain = ctrl.Result{Requeue: true, RequeueAfter: reconcileInterval}
)

// SetupWithManager sets up the controller with the Manager.
func (r *VGReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&lvmv1alpha1.LVMVolumeGroup{}).
		Owns(&lvmv1alpha1.LVMVolumeGroupNodeStatus{}, builder.MatchEveryOwner, builder.WithPredicates(predicate.GenerationChangedPredicate{})).
		Complete(r)
}

type VGReconciler struct {
	client.Client
	Scheme *runtime.Scheme
	record.EventRecorder
	LVMD lvmd.Configurator
	lvm.LVM
	lsblk.LSBLK
	wipefs.Wipefs
	dmsetup.Dmsetup
	NodeName  string
	Namespace string
	Filters   func(*lvmv1alpha1.LVMVolumeGroup, lvm.LVM, lsblk.LSBLK) filter.Filters
}

func (r *VGReconciler) getFinalizer() string {
	return fmt.Sprintf("%s/%s", NodeCleanupFinalizer, r.NodeName)
}

func (r *VGReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	logger := log.FromContext(ctx)
	logger.Info("reconciling")

	// Check if this LVMVolumeGroup needs to be processed on this node
	volumeGroup := &lvmv1alpha1.LVMVolumeGroup{}
	if err := r.Client.Get(ctx, req.NamespacedName, volumeGroup); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

	// Check if the nodeSelector matches the labels on this node
	nodeMatches, err := r.matchesThisNode(ctx, volumeGroup.Spec.NodeSelector)
	if err != nil {
		return ctrl.Result{}, fmt.Errorf("failed to match nodeSelector to node labels: %w", err)
	}
	if !nodeMatches {
		// Nothing to be done on this node for the VG.
		logger.Info("node labels do not match the selector", "VGName", volumeGroup.Name)
		return ctrl.Result{}, nil
	}

	nodeStatus := r.getLVMVolumeGroupNodeStatus()
	if err := r.Get(ctx, client.ObjectKeyFromObject(nodeStatus), nodeStatus); err != nil {
		if errors.IsNotFound(err) {
			if err := r.Create(ctx, nodeStatus); err != nil {
				return ctrl.Result{}, fmt.Errorf("could not create previously non-existing LVMVolumeGroupNodeStatus: %w", err)
			}
		} else {
			return ctrl.Result{}, fmt.Errorf("could not determine if LVMVolumeGroupNodeStatus still needs to be created: %w", err)
		}
	}

	return r.reconcile(ctx, volumeGroup, nodeStatus)
}

func (r *VGReconciler) reconcile(
	ctx context.Context,
	volumeGroup *lvmv1alpha1.LVMVolumeGroup,
	nodeStatus *lvmv1alpha1.LVMVolumeGroupNodeStatus,
) (ctrl.Result, error) {
	logger := log.FromContext(ctx)
	// Check if the LVMVolumeGroup resource is deleted
	if !volumeGroup.DeletionTimestamp.IsZero() {
		return ctrl.Result{}, r.processDelete(ctx, volumeGroup)
	} else {
		if added := controllerutil.AddFinalizer(volumeGroup, r.getFinalizer()); added {
			logger.Info("adding finalizer")
			return ctrl.Result{}, r.Client.Update(ctx, volumeGroup)
		}
	}

	// Read the lvmd config file
	lvmdConfig, err := r.LVMD.Load()
	if err != nil {
		err = fmt.Errorf("failed to read the lvmd config file: %w", err)
		if _, err := r.setVolumeGroupFailedStatus(ctx, volumeGroup, nil, err); err != nil {
			logger.Error(err, "failed to set status to failed")
		}
		return ctrl.Result{}, err
	}

	lvmdConfigWasMissing := false
	if lvmdConfig == nil {
		lvmdConfigWasMissing = true
		lvmdConfig = &lvmd.Config{
			SocketName: controllers.DefaultLVMdSocket,
		}
	}
	existingLvmdConfig := *lvmdConfig

	blockDevices, err := r.LSBLK.ListBlockDevices()
	if err != nil {
		return ctrl.Result{}, fmt.Errorf("failed to list block devices: %w", err)
	}

	wiped, err := r.wipeDevicesIfNecessary(ctx, volumeGroup, nodeStatus, blockDevices)
	if err != nil {
		return ctrl.Result{}, fmt.Errorf("failed to wipe devices: %w", err)
	}
	if wiped {
		blockDevices, err = r.LSBLK.ListBlockDevices()
		if err != nil {
			return ctrl.Result{}, fmt.Errorf("failed to list block devices: %w", err)
		}
	}

	// Get the available block devices that can be used for this volume group
	// valid means that it can be used to create or extend the volume group
	// devices that are already part of the volume group will not be returned
	newDevices, err := r.getNewDevicesToBeAdded(ctx, blockDevices, nodeStatus, volumeGroup)
	if err != nil {
		return ctrl.Result{}, fmt.Errorf("failed to get matching available block devices for volumegroup %s: %w", volumeGroup.GetName(), err)
	}

	devices := r.filterDevices(ctx, newDevices, r.Filters(volumeGroup, r.LVM, r.LSBLK))

	vgs, err := r.LVM.ListVGs()
	if err != nil {
		return ctrl.Result{}, fmt.Errorf("failed to list volume groups: %w", err)
	}

	vgExistsInLVM := false
	for _, vg := range vgs {
		if volumeGroup.Name == vg.Name {
			if len(vg.PVs) > 0 {
				vgExistsInLVM = true
			}
		}
	}

	// If there are no available devices, that could mean either
	// - There is no available devices to attach to the volume group
	// - All the available devices are already attached
	if len(devices.Available) == 0 {
		if !vgExistsInLVM {
			err := fmt.Errorf("the volume group %s does not exist and there were no available devices to create it", volumeGroup.GetName())
			r.WarningEvent(ctx, volumeGroup, EventReasonErrorNoAvailableDevicesForVG, err)
			if _, err := r.setVolumeGroupFailedStatus(ctx, volumeGroup, devices, err); err != nil {
				logger.Error(err, "failed to set status to failed")
			}
			return ctrl.Result{}, err
		}

		logger.Info("no new available devices discovered, verifying existing setup")

		// since the last reconciliation there could have been corruption on the LVs so we need to verify them again
		if err := r.validateLVs(ctx, volumeGroup); err != nil {
			err := fmt.Errorf("error while validating logical volumes in existing volume group: %w", err)
			r.WarningEvent(ctx, volumeGroup, EventReasonErrorInconsistentLVs, err)
			if _, err := r.setVolumeGroupFailedStatus(ctx, volumeGroup, devices, err); err != nil {
				logger.Error(err, "failed to set status to failed")
			}
			return ctrl.Result{}, err
		}

		msg := "all the available devices are attached to the volume group"
		logger.Info(msg)
		if updated, err := r.setVolumeGroupReadyStatus(ctx, volumeGroup, devices); err != nil {
			return ctrl.Result{}, fmt.Errorf("failed to set status for volume group %s to ready: %w", volumeGroup.Name, err)
		} else if updated {
			r.NormalEvent(ctx, volumeGroup, EventReasonVolumeGroupReady, msg)
		}

		return reconcileAgain, nil
	} else {
		if updated, err := r.setVolumeGroupProgressingStatus(ctx, volumeGroup, devices); err != nil {
			logger.Error(err, "failed to set status to progressing")
		} else if updated {
			logger.Info("new available devices were discovered and status was updated to progressing")
			return ctrl.Result{Requeue: true}, nil
		}
	}

	logger.Info("new available devices discovered", "available", devices.Available)

	// Create VG/extend VG
	if err = r.addDevicesToVG(ctx, vgs, volumeGroup.Name, devices.Available); err != nil {
		err = fmt.Errorf("failed to create/extend volume group %s: %w", volumeGroup.Name, err)
		r.WarningEvent(ctx, volumeGroup, EventReasonErrorVGCreateOrExtendFailed, err)
		if _, err := r.setVolumeGroupFailedStatus(ctx, volumeGroup, devices, err); err != nil {
			logger.Error(err, "failed to set status to failed")
		}
		return ctrl.Result{}, err
	}

	// Create thin pool
	if err = r.addThinPoolToVG(ctx, volumeGroup.Name, volumeGroup.Spec.ThinPoolConfig); err != nil {
		err := fmt.Errorf("failed to create thin pool %s for volume group %s: %w", volumeGroup.Spec.ThinPoolConfig.Name, volumeGroup.Name, err)
		r.WarningEvent(ctx, volumeGroup, EventReasonErrorThinPoolCreateOrExtendFailed, err)
		if _, err := r.setVolumeGroupFailedStatus(ctx, volumeGroup, devices, err); err != nil {
			logger.Error(err, "failed to set status to failed")
		}
		return ctrl.Result{}, err
	}

	// Validate the LVs created from the Thin-Pool to make sure the adding went as planned.
	if err := r.validateLVs(ctx, volumeGroup); err != nil {
		err := fmt.Errorf("error while validating logical volumes in existing volume group: %w", err)
		r.WarningEvent(ctx, volumeGroup, EventReasonErrorInconsistentLVs, err)
		if _, err := r.setVolumeGroupFailedStatus(ctx, volumeGroup, devices, err); err != nil {
			logger.Error(err, "failed to set status to failed")
		}
		return ctrl.Result{}, err
	}

	// Add the volume group to device classes inside lvmd config if not exists
	found := false
	for _, deviceClass := range lvmdConfig.DeviceClasses {
		if deviceClass.Name == volumeGroup.Name {
			found = true
		}
	}
	if !found {
		dc := &lvmd.DeviceClass{
			Name:           volumeGroup.Name,
			VolumeGroup:    volumeGroup.Name,
			Default:        volumeGroup.Spec.Default,
			ThinPoolConfig: &lvmd.ThinPoolConfig{},
		}

		if volumeGroup.Spec.ThinPoolConfig != nil {
			dc.Type = lvmd.TypeThin
			dc.ThinPoolConfig.Name = volumeGroup.Spec.ThinPoolConfig.Name
			dc.ThinPoolConfig.OverprovisionRatio = float64(volumeGroup.Spec.ThinPoolConfig.OverprovisionRatio)
		}

		lvmdConfig.DeviceClasses = append(lvmdConfig.DeviceClasses, dc)
	}

	// Apply and save lvmd config
	if !cmp.Equal(existingLvmdConfig, lvmdConfig) {
		if lvmdConfigWasMissing {
			// The lvmdconfig file does not exist and will be created.
			msg := "lvmd config file doesn't exist, will attempt to create a fresh config"
			logger.Info(msg)
			r.NormalEvent(ctx, volumeGroup, EventReasonLVMDConfigMissing, msg)
		}

		if err := r.LVMD.Save(lvmdConfig); err != nil {
			err := fmt.Errorf("failed to update lvmd config file to update volume group %s: %w", volumeGroup.GetName(), err)
			if _, err := r.setVolumeGroupFailedStatus(ctx, volumeGroup, devices, err); err != nil {
				logger.Error(err, "failed to set status to failed")
			}
			return ctrl.Result{}, err
		}
		msg := "updated lvmd config with new deviceClasses"
		logger.Info(msg)
		r.NormalEvent(ctx, volumeGroup, EventReasonLVMDConfigUpdated, msg)
	}

	if updated, err := r.setVolumeGroupReadyStatus(ctx, volumeGroup, devices); err != nil {
		return ctrl.Result{}, fmt.Errorf("failed to set status for volume group %s to ready: %w", volumeGroup.Name, err)
	} else if updated {
		msg := "all the available devices are attached to the volume group"
		r.NormalEvent(ctx, volumeGroup, EventReasonVolumeGroupReady, msg)
	}

	return reconcileAgain, nil
}

func (r *VGReconciler) processDelete(ctx context.Context, volumeGroup *lvmv1alpha1.LVMVolumeGroup) error {
	logger := log.FromContext(ctx).WithValues("VGName", volumeGroup.Name)
	logger.Info("deleting")

	// Read the lvmd config file
	lvmdConfig, err := r.LVMD.Load()
	if err != nil {
		// Failed to read lvmdconfig file. Reconcile again
		return fmt.Errorf("failed to read the lvmd config file: %w", err)
	}
	if lvmdConfig == nil {
		logger.Info("lvmd config file does not exist, assuming deleted")
	} else {
		found := false
		for i, deviceClass := range lvmdConfig.DeviceClasses {
			if deviceClass.Name == volumeGroup.Name {
				// Remove this vg from the lvmdconf file
				lvmdConfig.DeviceClasses = append(lvmdConfig.DeviceClasses[:i], lvmdConfig.DeviceClasses[i+1:]...)
				found = true
				break
			}
		}
		if !found {
			logger.Info("could not find volume group in lvmd deviceclasses list, assuming deleted")
		}
	}

	// Check if volume group exists
	vg, err := r.LVM.GetVG(volumeGroup.Name)
	if err != nil {
		if err != lvm.ErrVolumeGroupNotFound {
			return fmt.Errorf("failed to get volume group %s, %w", volumeGroup.GetName(), err)
		}
		logger.Info("volume group not found, assuming it was already deleted and continuing")
	} else {
		// Delete thin pool
		if volumeGroup.Spec.ThinPoolConfig != nil {
			thinPoolName := volumeGroup.Spec.ThinPoolConfig.Name
			logger := logger.WithValues("ThinPool", thinPoolName)
			thinPoolExists, err := r.LVM.LVExists(thinPoolName, volumeGroup.Name)
			if err != nil {
				return fmt.Errorf("failed to check existence of thin pool %q in volume group %q. %v", thinPoolName, volumeGroup.Name, err)
			}

			if thinPoolExists {
				if err := r.LVM.DeleteLV(thinPoolName, volumeGroup.Name); err != nil {
					err := fmt.Errorf("failed to delete thin pool %s in volume group %s: %w", thinPoolName, volumeGroup.Name, err)
					if _, err := r.setVolumeGroupFailedStatus(ctx, volumeGroup, nil, err); err != nil {
						logger.Error(err, "failed to set status to failed")
					}
					return err
				}
				logger.Info("thin pool deleted")
			} else {
				logger.Info("thin pool not found, assuming it was already deleted and continuing")
			}
		}

		if err = r.LVM.DeleteVG(vg); err != nil {
			err := fmt.Errorf("failed to delete volume group %s: %w", volumeGroup.Name, err)
			if _, err := r.setVolumeGroupFailedStatus(ctx, volumeGroup, nil, err); err != nil {
				logger.Error(err, "failed to set status to failed", "VGName", volumeGroup.GetName())
			}
			return err
		}
		logger.Info("volume group deleted")
	}

	// in case we have an existing LVMDConfig, we either need to update it if there are still deviceClasses remaining
	// or delete it, if we are dealing with the last deviceClass that is about to be removed.
	// if there was no config file in the first place, nothing has to be removed.
	if lvmdConfig != nil {
		if len(lvmdConfig.DeviceClasses) > 0 {
			if err = r.LVMD.Save(lvmdConfig); err != nil {
				return fmt.Errorf("failed to update lvmd.conf file for volume group %s: %w", volumeGroup.GetName(), err)
			}
			msg := "updated lvmd config after deviceClass was removed"
			logger.Info(msg)
			r.NormalEvent(ctx, volumeGroup, EventReasonLVMDConfigUpdated, msg)
		} else {
			if err = r.LVMD.Delete(); err != nil {
				return fmt.Errorf("failed to delete lvmd.conf file for volume group %s: %w", volumeGroup.GetName(), err)
			}
			msg := "removed lvmd config after last deviceClass was removed"
			logger.Info(msg)
			r.NormalEvent(ctx, volumeGroup, EventReasonLVMDConfigDeleted, msg)
		}
	}

	if err := r.removeVolumeGroupStatus(ctx, volumeGroup); err != nil {
		return fmt.Errorf("failed to remove status for volume group %s: %w", volumeGroup.Name, err)
	}

	if removed := controllerutil.RemoveFinalizer(volumeGroup, r.getFinalizer()); removed {
		logger.Info("removing finalizer")
		return r.Client.Update(ctx, volumeGroup)
	}
	return nil
}

// validateLVs verifies that all lvs that should have been created in the volume group are present and
// in their correct state
func (r *VGReconciler) validateLVs(ctx context.Context, volumeGroup *lvmv1alpha1.LVMVolumeGroup) error {
	logger := log.FromContext(ctx)

	// If we don't have a ThinPool, VG Manager has no authority about the top Level LVs inside the VG, but TopoLVM
	if volumeGroup.Spec.ThinPoolConfig == nil {
		return nil
	}

	resp, err := r.LVM.ListLVs(volumeGroup.Name)
	if err != nil {
		return fmt.Errorf("could not get logical volumes found inside volume group, volume group content is degraded or corrupt: %w", err)
	}
	if len(resp.Report) < 1 {
		return fmt.Errorf("LV report was empty, meaning that the thin-pool LV is no longer found, " +
			"but the volume group might still exist")
	}

	for _, report := range resp.Report {
		if len(report.Lv) < 1 {
			return fmt.Errorf("no LV was found in the report, meaning that the thin-pool LV is no longer found, " +
				"but the volume group might still exist")
		}
		thinPoolExists := false
		for _, lv := range report.Lv {
			if lv.Name != volumeGroup.Spec.ThinPoolConfig.Name {
				continue
			}
			thinPoolExists = true
			lvAttr, err := ParsedLvAttr(lv.LvAttr)
			if err != nil {
				return fmt.Errorf("could not parse lv_attr from logical volume %s: %w", lv.Name, err)
			}
			if lvAttr.VolumeType != VolumeTypeThinPool {
				return fmt.Errorf("found logical volume in volume group that is not of type Thin-Pool, "+
					"even though there is a Thin-Pool configured: %s, lv_attr: %s,"+
					"this is most likely a corruption of the thin pool or a setup gone wrong",
					string(lvAttr.VolumeType), lvAttr)
			}

			if lvAttr.State != StateActive {
				return fmt.Errorf("found inactive logical volume, maybe external repairs are necessary/already happening or there is another"+
					"entity conflicting with vg-manager, cannot proceed until volume is activated again: lv_attr: %s", lvAttr)
			}
			metadataPercentage, err := strconv.ParseFloat(lv.MetadataPercent, 32)
			if err != nil {
				return fmt.Errorf("could not ensure metadata percentage of LV due to a parsing error: %w", err)
			}
			if metadataPercentage > metadataWarningPercentage {
				return fmt.Errorf("metadata partition is over %v percent filled and LVM Metadata Overflows cannot be recovered"+
					"you should manually extend the metadata_partition or you will risk data loss: metadata_percent: %v", metadataPercentage, lv.MetadataPercent)
			}

			logger.V(1).Info("confirmed created logical volume has correct attributes", "lv_attr", lvAttr.String())
		}
		if !thinPoolExists {
			return fmt.Errorf("the thin-pool LV is no longer present, but the volume group might still exist")
		}
	}
	return nil
}

func (r *VGReconciler) addThinPoolToVG(ctx context.Context, vgName string, config *lvmv1alpha1.ThinPoolConfig) error {
	logger := log.FromContext(ctx).WithValues("VGName", vgName, "ThinPool", config.Name)

	resp, err := r.LVM.ListLVs(vgName)
	if err != nil {
		return fmt.Errorf("failed to list logical volumes in the volume group %q. %v", vgName, err)
	}

	for _, report := range resp.Report {
		for _, lv := range report.Lv {
			if lv.Name == config.Name {
				lvAttr, err := ParsedLvAttr(lv.LvAttr)
				if err != nil {
					return fmt.Errorf("could not parse lvattr to determine if thin pool exists: %w", err)
				}
				if lvAttr.VolumeType == VolumeTypeThinPool {
					logger.Info("lvm thinpool already exists")
					if err := r.extendThinPool(ctx, vgName, lv.LvSize, config); err != nil {
						return fmt.Errorf("failed to extend the lvm thinpool %s in volume group %s: %w", config.Name, vgName, err)
					}
					return nil
				}

				return fmt.Errorf("failed to create thin pool %q, logical volume with same name already exists, but cannot be extended as its not a thinpool (%s)", config.Name, lvAttr)
			}
		}
	}

	logger.Info("creating lvm thinpool")
	if err := r.LVM.CreateLV(config.Name, vgName, config.SizePercent); err != nil {
		return fmt.Errorf("failed to create thinpool: %w", err)
	}
	logger.Info("successfully created thinpool")

	return nil
}

func (r *VGReconciler) extendThinPool(ctx context.Context, vgName string, lvSize string, config *lvmv1alpha1.ThinPoolConfig) error {
	logger := log.FromContext(ctx).WithValues("VGName", vgName, "ThinPool", config.Name)

	vg, err := r.LVM.GetVG(vgName)
	if err != nil {
		if err != lvm.ErrVolumeGroupNotFound {
			return fmt.Errorf("failed to get volume group. %q, %v", vgName, err)
		}
		return nil
	}

	thinPoolSize, err := strconv.ParseFloat(lvSize[:len(lvSize)-1], 64)
	if err != nil {
		return fmt.Errorf("failed to parse lvSize. %v", err)
	}

	vgSize, err := strconv.ParseFloat(vg.VgSize[:len(vg.VgSize)-1], 64)
	if err != nil {
		return fmt.Errorf("failed to parse vgSize. %v", err)
	}

	// return if thinPoolSize does not require expansion
	if config.SizePercent <= int((thinPoolSize/vgSize)*100) {
		return nil
	}

	logger.Info("extending lvm thinpool")
	if err := r.LVM.ExtendLV(config.Name, vgName, config.SizePercent); err != nil {
		return fmt.Errorf("failed to extend thinpool: %w", err)
	}
	logger.Info("successfully extended thinpool")

	return nil
}

func (r *VGReconciler) matchesThisNode(ctx context.Context, selector *corev1.NodeSelector) (bool, error) {
	node := &corev1.Node{}
	err := r.Client.Get(ctx, types.NamespacedName{Name: r.NodeName}, node)
	if err != nil {
		return false, err
	}
	if selector == nil {
		return true, nil
	}

	matches, err := corev1helper.MatchNodeSelectorTerms(node, selector)
	return matches, err
}

// WarningEvent sends an event to both the nodeStatus, and the affected processed volumeGroup as well as the owning LVMCluster if present
func (r *VGReconciler) WarningEvent(ctx context.Context, obj *lvmv1alpha1.LVMVolumeGroup, reason EventReasonError, err error) {
	nodeStatus := &lvmv1alpha1.LVMVolumeGroupNodeStatus{}
	nodeStatus.SetName(r.NodeName)
	nodeStatus.SetNamespace(r.Namespace)
	// even if the get does not succeed we can still issue an event, just without UUID / resourceVersion
	_ = r.Get(ctx, client.ObjectKeyFromObject(nodeStatus), nodeStatus)
	r.Event(nodeStatus, corev1.EventTypeWarning, string(reason), err.Error())
	for _, ref := range obj.GetOwnerReferences() {
		owner := &v1.PartialObjectMetadata{}
		owner.SetName(ref.Name)
		owner.SetNamespace(obj.GetNamespace())
		owner.SetUID(ref.UID)
		owner.SetGroupVersionKind(schema.FromAPIVersionAndKind(ref.APIVersion, ref.Kind))
		r.Event(owner, corev1.EventTypeWarning, string(reason),
			fmt.Errorf("error on node %s in volume group %s: %w",
				client.ObjectKeyFromObject(nodeStatus), client.ObjectKeyFromObject(obj), err).Error())
	}
	r.Event(obj, corev1.EventTypeWarning, string(reason),
		fmt.Errorf("error on node %s: %w", client.ObjectKeyFromObject(nodeStatus), err).Error())
}

// NormalEvent sends an event to both the nodeStatus, and the affected processed volumeGroup as well as the owning LVMCluster if present
func (r *VGReconciler) NormalEvent(ctx context.Context, obj *lvmv1alpha1.LVMVolumeGroup, reason EventReasonInfo, message string) {
	if !log.FromContext(ctx).V(1).Enabled() {
		return
	}
	nodeStatus := &lvmv1alpha1.LVMVolumeGroupNodeStatus{}
	nodeStatus.SetName(r.NodeName)
	nodeStatus.SetNamespace(r.Namespace)
	// even if the get does not succeed we can still issue an event, just without UUID / resourceVersion
	_ = r.Get(ctx, client.ObjectKeyFromObject(nodeStatus), nodeStatus)
	r.Event(nodeStatus, corev1.EventTypeNormal, string(reason), message)
	for _, ref := range obj.GetOwnerReferences() {
		owner := &v1.PartialObjectMetadata{}
		owner.SetName(ref.Name)
		owner.SetNamespace(obj.GetNamespace())
		owner.SetUID(ref.UID)
		owner.SetGroupVersionKind(schema.FromAPIVersionAndKind(ref.APIVersion, ref.Kind))
		r.Event(owner, corev1.EventTypeNormal, string(reason),
			fmt.Sprintf("update on node %s in volume group %s: %s",
				client.ObjectKeyFromObject(nodeStatus), client.ObjectKeyFromObject(obj), message))
	}
	r.Event(obj, corev1.EventTypeNormal, string(reason),
		fmt.Sprintf("update on node %s: %s", client.ObjectKeyFromObject(nodeStatus), message))
}
