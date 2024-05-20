// Copyright 2021-2022 vArmor Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package apparmor

const alwaysAllowTemplate = `
## == Managed by vArmor == ##

abi <abi/3.0>,
#include <tunables/global>

profile %s flags=(attach_disconnected,mediate_deleted) {

  #include <abstractions/base>

  file,
  capability,
  network,
  mount,
  remount,
  umount,
  pivot_root,
  ptrace,
  signal,
  dbus,
  unix,

%s
}
`

const alwaysAllowChildTemplate = `

%s
profile %s flags=(attach_disconnected,mediate_deleted) {
  %s
  #include <abstractions/base>

  file,
  capability,
  network,
  mount,
  remount,
  umount,
  pivot_root,
  ptrace,
  signal,
  dbus,
  unix,

%s
}
`

const runtimeDefaultTemplate = `
## == Managed by vArmor == ##

abi <abi/3.0>,
#include <tunables/global>

profile %s flags=(attach_disconnected,mediate_deleted) {

  #include <abstractions/base>

  network,
  capability,
  file,
  umount,

  # host (privileged) processes may send signals to container processes.
  signal (receive) peer=unconfined,
  # runc may send signals to container processes.
  signal (receive) peer=runc,
  # crun may send signals to container processes.
  signal (receive) peer=crun,
  # container processes may send signals amongst themselves.
  signal (send,receive) peer=%s,

  # deny write for all files directly in /proc (not in a subdir)
  deny @{PROC}/* w,
  # deny write to files not in /proc/<number>/** or /proc/sys/**
  deny @{PROC}/{[^1-9],[^1-9][^0-9],[^1-9s][^0-9y][^0-9s],[^1-9][^0-9][^0-9][^0-9]*}/** w,
  # deny /proc/sys except /proc/sys/k* (effectively /proc/sys/kernel)
  deny @{PROC}/sys/[^k]** w,
  # deny everything except shm* in /proc/sys/kernel/
  deny @{PROC}/sys/kernel/{?,??,[^s][^h][^m]**} w,
  deny @{PROC}/sysrq-trigger rwklx,
  deny @{PROC}/mem rwklx,
  deny @{PROC}/kmem rwklx,
  deny @{PROC}/kcore rwklx,

  deny mount,

  deny /sys/[^f]*/** wklx,
  deny /sys/f[^s]*/** wklx,
  deny /sys/fs/[^c]*/** wklx,
  deny /sys/fs/c[^g]*/** wklx,
  deny /sys/fs/cg[^r]*/** wklx,
  deny /sys/firmware/** rwklx,
  deny /sys/devices/virtual/powercap/** rwklx,
  deny /sys/kernel/security/** rwklx,

  # allow processes within the container to trace each other,
  # provided all other LSM and yama setting allow it.
  ptrace (trace,read,tracedby,readby) peer=%s,

%s
}
`

const runtimeDefaultChildTemplate = `

# processes with parent profile may send signal to processes with child profile
signal (send) peer=%s,
# processes with parent profile may ptrace processes with child profile, but not vice versa.
ptrace (trace,read) peer=%s,

%s
profile %s flags=(attach_disconnected,mediate_deleted) {
  %s
  #include <abstractions/base>

  network,
  capability,
  file,
  umount,

  # host (privileged) processes may send signals to container processes.
  signal (receive) peer=unconfined,
  # runc may send signals to container processes.
  signal (receive) peer=runc,
  # crun may send signals to container processes.
  signal (receive) peer=crun,
  # processes with child profile may receive signals from processes with parent profile.
  signal (receive) peer=%s,
  # processes with child profile may send signals amongst themselves.
  signal (send,receive) peer=%s,

  deny @{PROC}/* w,
  deny @{PROC}/{[^1-9],[^1-9][^0-9],[^1-9s][^0-9y][^0-9s],[^1-9][^0-9][^0-9][^0-9]*}/** w,
  deny @{PROC}/sys/[^k]** w,
  deny @{PROC}/sys/kernel/{?,??,[^s][^h][^m]**} w,
  deny @{PROC}/sysrq-trigger rwklx,
  deny @{PROC}/mem rwklx,
  deny @{PROC}/kmem rwklx,
  deny @{PROC}/kcore rwklx,

  deny mount,

  deny /sys/[^f]*/** wklx,
  deny /sys/f[^s]*/** wklx,
  deny /sys/fs/[^c]*/** wklx,
  deny /sys/fs/c[^g]*/** wklx,
  deny /sys/fs/cg[^r]*/** wklx,
  deny /sys/firmware/** rwklx,
  deny /sys/devices/virtual/powercap/** rwklx,
  deny /sys/kernel/security/** rwklx,

  # processes with parent profile may ptrace processes with child profile, but not vice versa.
  ptrace (tracedby,readby) peer=%s,
  # processes with child profile may ptrace processes amongst themselves.
  ptrace (trace,read,tracedby,readby) peer=%s,

%s
}
`

const customPolicyRulesTemplate = `
## == Managed by vArmor == ##

abi <abi/3.0>,
#include <tunables/global>

profile %s flags=(attach_disconnected,mediate_deleted) {

%s
}
`

const behaviorModelingTemplate = `
## == Managed by vArmor == ##

abi <abi/3.0>,
#include <tunables/global>

profile %s flags=(attach_disconnected,mediate_deleted) {
}
`

const defenseInDepthTemplate = `
## == Managed by vArmor == ##

abi <abi/3.0>,
#include <tunables/global>

profile %s flags=(attach_disconnected,mediate_deleted) {

  #include <abstractions/base>
%s
}
`
