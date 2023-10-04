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

package lvm

import (
	"fmt"
	"strings"
	"testing"

	"github.com/openshift/lvm-operator/internal/controllers/vgmanager/exec/test"
	"github.com/stretchr/testify/assert"
)

var mockVgsOutput = `{
	"report": [
		{
			"vg": [
				{"vg_name":"vg1", "pv_count":"3", "lv_count":"3", "snap_count":"0", "vg_attr":"wz--n-", "vg_size":"<475.94g", "vg_free":"0 "},
				{"vg_name":"vg2", "pv_count":"3", "lv_count":"3", "snap_count":"0", "vg_attr":"wz--n-", "vg_size":"<475.94g", "vg_free":"0 "}
			]
		}
	]
}`

var mockPvsOutputForVG1 = `
{
	"report": [
		{
			"pv": [
				{"pv_name":"/dev/sda", "vg_name":"vg1", "pv_fmt":"lvm2", "pv_attr":"a--", "pv_size":"<475.94g", "pv_free":"0 "},
				{"pv_name":"/dev/sdb", "vg_name":"vg1", "pv_fmt":"lvm2", "pv_attr":"a--", "pv_size":"<475.94g", "pv_free":"0 "},
				{"pv_name":"/dev/sdc", "vg_name":"vg1", "pv_fmt":"lvm2", "pv_attr":"a--", "pv_size":"<475.94g", "pv_free":"0 "}
			]
		}
	]
}
`

var mockPvsOutputForVG2 = `
{
	"report": [
		{
			"pv": [
				{"pv_name":"/dev/sdd", "vg_name":"vg2", "pv_fmt":"lvm2", "pv_attr":"a--", "pv_size":"<475.94g", "pv_free":"0 "},
				{"pv_name":"/dev/sde", "vg_name":"vg2", "pv_fmt":"lvm2", "pv_attr":"a--", "pv_size":"<475.94g", "pv_free":"0 "}
			]
		}
	]
}
`

func TestGetVolumeGroup(t *testing.T) {
	tests := []struct {
		name    string
		vgName  string
		pvCount int
		wantErr bool
	}{
		{"Invalid volume group name", "invalid-vg", 0, true},
		{"Valid volume group name", "vg1", 3, false},
		{"Valid volume group name", "vg2", 2, false},
	}
	executor := &test.MockExecutor{
		MockExecuteCommandWithOutputAsHost: func(command string, args ...string) (string, error) {
			if args[0] == "vgs" {
				return mockVgsOutput, nil
			} else if args[0] == "pvs" {
				argsConcat := strings.Join(args, " ")
				out := "pvs --units g -v --reportformat json -S vgname=%s"
				if argsConcat == fmt.Sprintf(out, "vg1") {
					return mockPvsOutputForVG1, nil
				} else if argsConcat == fmt.Sprintf(out, "vg2") {
					return mockPvsOutputForVG2, nil
				}
			}
			return "", fmt.Errorf("invalid args %q", args[0])
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			vg, err := NewHostLVM(executor).GetVG(tt.vgName)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.vgName, vg.Name)
				assert.Equal(t, tt.pvCount, len(vg.PVs))
			}
		})
	}
}

func TestListVolumeGroup(t *testing.T) {
	tests := []struct {
		name    string
		wantErr bool
	}{
		{"List all volume groups", false},
	}
	executor := &test.MockExecutor{
		MockExecuteCommandWithOutputAsHost: func(command string, args ...string) (string, error) {
			if args[0] == "vgs" {
				return mockVgsOutput, nil
			} else if args[0] == "pvs" {
				argsConcat := strings.Join(args, " ")
				out := "pvs --units g -v --reportformat json -S vgname=%s"
				if argsConcat == fmt.Sprintf(out, "vg1") {
					return mockPvsOutputForVG1, nil
				} else if argsConcat == fmt.Sprintf(out, "vg2") {
					return mockPvsOutputForVG2, nil
				}
			}
			return "", fmt.Errorf("invalid args %q", args[0])
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			vgs, err := NewHostLVM(executor).ListVGs()
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				for _, vg := range vgs {
					if vg.Name == "vg1" {
						assert.Equal(t, 3, len(vg.PVs))
					} else if vg.Name == "vg2" {
						assert.Equal(t, 2, len(vg.PVs))
					}
				}
			}
		})
	}
}

func TestCreateVolumeGroup(t *testing.T) {
	tests := []struct {
		name        string
		volumeGroup VolumeGroup
		wantErr     bool
	}{
		{"No Volume Group Name", VolumeGroup{}, true},
		{"No Physical Volumes", VolumeGroup{Name: "vg1"}, true},
		{"Volume Group created successfully", VolumeGroup{Name: "vg1", PVs: []PhysicalVolume{{PvName: "/dev/sdb"}}}, false},
	}

	executor := &test.MockExecutor{
		MockExecuteCommandWithOutputAsHost: func(command string, args ...string) (string, error) {
			return "", nil
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := NewHostLVM(executor).CreateVG(tt.volumeGroup)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestExtendVolumeGroup(t *testing.T) {
	tests := []struct {
		name        string
		volumeGroup VolumeGroup
		PVs         []string
		wantErr     bool
	}{
		{"No PVs are available", VolumeGroup{Name: "vg1"}, []string{}, true},
		{"New PVs are available", VolumeGroup{Name: "vg1"}, []string{"/dev/sdb", "/dev/sdc"}, false},
	}

	executor := &test.MockExecutor{
		MockExecuteCommandWithOutputAsHost: func(command string, args ...string) (string, error) {
			return "", nil
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			newVG, err := NewHostLVM(executor).ExtendVG(tt.volumeGroup, tt.PVs)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
			newPVs := make([]string, len(newVG.PVs))
			for i, pv := range newVG.PVs {
				newPVs[i] = pv.PvName
			}
			assert.ElementsMatch(t, newPVs, tt.PVs)
		})
	}
}