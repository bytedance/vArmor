/*
Copyright The vArmor Authors.

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

package v1beta1

type AppArmorRawRules struct {
	// rules defines the custom AppArmor rules. You should ensure they conform to AppArmor syntax on
	// your own.
	Rules string `json:"rules"`
	// targets specifies the executable files for which the rules apply. They must be specified as
	// full paths to the executable files.
	// +optional
	Targets []string `json:"targets,omitempty"`
}

type AppArmorProfile struct {
	// profileType indicates which kind of AppArmor profile will be applied. Valid options are:
	// BehaviorModel - a profile generated via the BehaviorModeling mode will be used.
	// Custom - a custom profile defined in the customProfile field will be used.
	ProfileType ProfileType `json:"profileType"`
	// customProfile holds the user-defined AppArmor profile content. It must be a valid profile that
	// conforms to AppArmor syntax. If you want vArmor to apply the profile to target workloads automatically,
	// the profile's name must match the ArmorProfile object name. For example:
	//
	// abi <abi/3.0>,
	// #include <tunables/global>
	// profile varmor-demo-demo-4 flags=(attach_disconnected,mediate_deleted) {
	//   #include <abstractions/base>
	//   file,
	//   network,
	// }
	//
	// The profile name "varmor-demo-demo-4" is identical to the ArmorProfile object name.
	// +optional
	CustomProfile string `json:"customProfile,omitempty"`
	// appArmorRawRules specifies custom AppArmor rules. These rules will be added to the end of the
	// AppArmor profile that you specified.
	// +optional
	AppArmorRawRules []AppArmorRawRules `json:"appArmorRawRules,omitempty"`
}
