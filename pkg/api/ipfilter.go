/*
 * Copyright (c) 2022 NetLOX Inc
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package api

import (
	"fmt"
	"sort"
)

type IPFilter struct {
	CommonAPI
}

type IPFilterInformationGet struct {
	IPFilterInfo []IPFilterMod `json:"ipFilterAttr"`
}

// IPFilterMod - Info related to an IP filter entry
type IPFilterMod struct {
	// IPPrefix - IP address in CIDR notation (e.g., "192.168.1.0/24", "10.0.0.5/32")
	IPPrefix string `json:"cidr" yaml:"cidr"`
	// Action - Filter action: "allow" or "drop"
	Action string `json:"action" yaml:"action"`
	// FilterType - Map type: "blacklist" or "whitelist"
	FilterType string `json:"filterType,omitempty" yaml:"filterType,omitempty"`
	// Zone - Security zone (0 = all zones, >0 = specific zone)
	Zone uint16 `json:"zone,omitempty" yaml:"zone,omitempty"`
	// Priority - Rule priority (higher = more important)
	Priority uint16 `json:"priority,omitempty" yaml:"priority,omitempty"`
	// MapType - Map type for deletion: "blacklist" or "whitelist"
	MapType string `json:"mapType,omitempty" yaml:"mapType,omitempty"`
	// Statistics - Read-only statistics
	Packets uint64 `json:"packets,omitempty" yaml:"packets,omitempty"`
	Bytes   uint64 `json:"bytes,omitempty" yaml:"bytes,omitempty"`
}

type ConfigurationIPFilterFile struct {
	TypeMeta   `yaml:",inline"`
	ObjectMeta `yaml:"metadata,omitempty"`
	Spec       IPFilterMod `yaml:"spec"`
}

func (ipf IPFilterMod) Key() string {
	return fmt.Sprintf("%s|%s|%d|%d",
		ipf.IPPrefix, ipf.Action, ipf.Zone, ipf.Priority)
}

func (ipfresp IPFilterInformationGet) Sort() {
	sort.Slice(ipfresp.IPFilterInfo, func(i, j int) bool {
		return ipfresp.IPFilterInfo[i].Key() < ipfresp.IPFilterInfo[j].Key()
	})
}
