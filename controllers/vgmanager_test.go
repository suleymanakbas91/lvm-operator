/*
Copyright 2022 Red Hat Openshift Data Foundation.

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

package controllers

import (
	"testing"

	snapapi "github.com/kubernetes-csi/external-snapshotter/client/v4/apis/volumesnapshot/v1"
	lvmv1alpha1 "github.com/red-hat-storage/lvm-operator/api/v1alpha1"
	"gotest.tools/v3/assert"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	storagev1 "k8s.io/api/storage/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
)

const (
	testNamespace = "default"
)

func newFakeLVMClusterReconciler(t *testing.T, objs ...client.Object) *LVMClusterReconciler {
	scheme, err := lvmv1alpha1.SchemeBuilder.Build()
	assert.NilError(t, err, "creating scheme")

	err = corev1.AddToScheme(scheme)
	assert.NilError(t, err, "adding corev1 to scheme")

	err = appsv1.AddToScheme(scheme)
	assert.NilError(t, err, "adding appsv1 to scheme")

	err = storagev1.AddToScheme(scheme)
	assert.NilError(t, err, "adding storagev1 to scheme")

	err = snapapi.AddToScheme(scheme)
	assert.NilError(t, err, "adding snapshot api to scheme")

	client := fake.NewClientBuilder().WithScheme(scheme).WithObjects(objs...).Build()

	return &LVMClusterReconciler{
		Client:    client,
		Scheme:    scheme,
		Log:       logf.Log.WithName("LVMCLusterTest"),
		Namespace: "default",
	}
}
