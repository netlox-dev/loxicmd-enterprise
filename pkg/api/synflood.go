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

type SYNFlood struct {
	CommonAPI
}

type SYNFloodInformationGet struct {
	SYNFloodInfo []SYNFloodEntry `json:"synfloodAttr"`
}

// SYNFloodConfig - Configuration for SYN flood protection
type SYNFloodConfig struct {
	// Enabled - Enable/disable SYN flood protection
	Enabled bool `json:"enabled" yaml:"enabled"`
	// SYNThreshold - SYN packet rate threshold (packets/sec)
	SYNThreshold uint32 `json:"synThreshold" yaml:"synThreshold"`
	// CookieThreshold - Threshold to activate SYN cookies (must be < SYNThreshold)
	CookieThreshold uint32 `json:"cookieThreshold" yaml:"cookieThreshold"`
	// WhitelistIPs - List of whitelisted IP addresses in CIDR notation
	WhitelistIPs []string `json:"whitelistIps" yaml:"whitelistIps"`
}

// SYNFloodStats - Statistics from SYN flood protection
type SYNFloodStats struct {
	TotalSYNs         uint64 `json:"totalSyns" yaml:"totalSyns"`
	BlockedSYNs       uint64 `json:"blockedSyns" yaml:"blockedSyns"`
	PassedSYNs        uint64 `json:"passedSyns" yaml:"passedSyns"`
	CookieActivations uint64 `json:"cookieActivations" yaml:"cookieActivations"`
	UniqueIPs         uint64 `json:"uniqueIps" yaml:"uniqueIps"`
}

// SYNFloodEntry - Combined configuration and statistics for API responses
type SYNFloodEntry struct {
	// Configuration fields
	Enabled         bool     `json:"enabled" yaml:"enabled"`
	SYNThreshold    uint32   `json:"synThreshold" yaml:"synThreshold"`
	CookieThreshold uint32   `json:"cookieThreshold" yaml:"cookieThreshold"`
	WhitelistIPs    []string `json:"whitelistIps" yaml:"whitelistIps"`
	// Statistics fields (read-only)
	TotalSYNs         uint64 `json:"totalSyns,omitempty" yaml:"totalSyns,omitempty"`
	BlockedSYNs       uint64 `json:"blockedSyns,omitempty" yaml:"blockedSyns,omitempty"`
	PassedSYNs        uint64 `json:"passedSyns,omitempty" yaml:"passedSyns,omitempty"`
	CookieActivations uint64 `json:"cookieActivations,omitempty" yaml:"cookieActivations,omitempty"`
	UniqueIPs         uint64 `json:"uniqueIps,omitempty" yaml:"uniqueIps,omitempty"`
}

type ConfigurationSYNFloodFile struct {
	TypeMeta   `yaml:",inline"`
	ObjectMeta `yaml:"metadata,omitempty"`
	Spec       SYNFloodConfig `yaml:"spec"`
}
