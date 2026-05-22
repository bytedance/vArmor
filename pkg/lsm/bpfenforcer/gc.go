// Copyright 2024 vArmor Authors
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

package bpfenforcer

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
)

// startupGC performs garbage collection on BPF maps at startup.
// It removes entries whose mount namespace IDs no longer correspond to
// any active process, preventing leaked entries from accumulating after
// agent crashes or abnormal restarts.
func (enforcer *BpfEnforcer) startupGC() {
	logger := enforcer.log.WithName("startupGC")

	activeNsIDs, err := getActiveMntNsIDs()
	if err != nil {
		logger.Error(err, "failed to get active mnt ns IDs, skipping startup GC")
		return
	}

	var nsID, mode uint32
	iter := enforcer.objs.V_profileMode.Iterate()
	var toDelete []uint32

	for iter.Next(&nsID, &mode) {
		if !activeNsIDs[nsID] {
			toDelete = append(toDelete, nsID)
		}
	}

	for _, ns := range toDelete {
		enforcer.deleteProfile(ns)
		_ = enforcer.removePodIps(ns)
	}

	if len(toDelete) > 0 {
		logger.Info("startup GC completed", "cleanedEntries", len(toDelete), "activeNamespaces", len(activeNsIDs))
	}
}

// getActiveMntNsIDs scans /proc to collect all active mount namespace IDs.
func getActiveMntNsIDs() (map[uint32]bool, error) {
	result := make(map[uint32]bool)

	entries, err := os.ReadDir("/proc")
	if err != nil {
		return nil, fmt.Errorf("failed to read /proc: %w", err)
	}

	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		// Only process numeric directories (PIDs)
		if _, err := strconv.Atoi(entry.Name()); err != nil {
			continue
		}

		link, err := os.Readlink(filepath.Join("/proc", entry.Name(), "ns", "mnt"))
		if err != nil {
			continue
		}

		// link format: "mnt:[4026531840]"
		var nsID uint64
		_, err = fmt.Sscanf(link, "mnt:[%d]", &nsID)
		if err != nil || nsID == 0 {
			continue
		}
		result[uint32(nsID)] = true
	}

	return result, nil
}
