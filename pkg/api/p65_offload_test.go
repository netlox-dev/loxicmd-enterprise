/*
 * Copyright (c) 2024 NetLOX Inc
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

// Phase 65 D-13: model-level tests for OffloadState + HwPkts fields on
// ConntrackInformation and LoadBalancerModel.  Runs on all platforms.
package api

import (
	"encoding/json"
	"testing"
)

// ---------------------------------------------------------------------------
// ConntrackInformation JSON round-trip tests
// ---------------------------------------------------------------------------

// TestConntrackOffloadFieldsPresent verifies OffloadState and HwPkts appear in
// JSON output when set (D-13: omitempty means absent only when zero/empty).
func TestConntrackOffloadFieldsPresent(t *testing.T) {
	ct := ConntrackInformation{
		Dip:          "10.0.0.2",
		Sip:          "10.0.0.1",
		Dport:        80,
		Sport:        54321,
		Proto:        "tcp",
		Pkts:         1000,
		Bytes:        65536,
		OffloadState: "hw",
		HwPkts:       12000,
	}
	b, err := json.Marshal(ct)
	if err != nil {
		t.Fatalf("json.Marshal: %v", err)
	}
	var m map[string]interface{}
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatalf("json.Unmarshal: %v", err)
	}
	if v, ok := m["offload_state"]; !ok || v != "hw" {
		t.Errorf("offload_state: want %q, got %v (present=%v)", "hw", v, ok)
	}
	if v, ok := m["hw_pkts"]; !ok {
		t.Errorf("hw_pkts: want 12000, got absent")
	} else if v.(float64) != 12000 {
		t.Errorf("hw_pkts: want 12000, got %v", v)
	}
}

// TestConntrackOffloadFieldsOmitted verifies OffloadState and HwPkts are absent
// from JSON when zero/empty — omitempty backward-compat for non-DOCA servers.
func TestConntrackOffloadFieldsOmitted(t *testing.T) {
	ct := ConntrackInformation{
		Dip:   "10.0.0.4",
		Sip:   "10.0.0.3",
		Dport: 443,
		Sport: 12345,
		Proto: "tcp",
		Pkts:  500,
		Bytes: 32768,
		// OffloadState and HwPkts intentionally zero
	}
	b, err := json.Marshal(ct)
	if err != nil {
		t.Fatalf("json.Marshal: %v", err)
	}
	var m map[string]interface{}
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatalf("json.Unmarshal: %v", err)
	}
	if _, ok := m["offload_state"]; ok {
		t.Errorf("offload_state should be absent (omitempty) when empty, but found in JSON")
	}
	if _, ok := m["hw_pkts"]; ok {
		t.Errorf("hw_pkts should be absent (omitempty) when 0, but found in JSON")
	}
}

// ---------------------------------------------------------------------------
// LoadBalancerModel JSON round-trip tests
// ---------------------------------------------------------------------------

// TestLbModelOffloadFieldsPresent verifies LoadBalancerModel OffloadState + HwPkts
// are serialized when set.
func TestLbModelOffloadFieldsPresent(t *testing.T) {
	lb := LoadBalancerModel{
		OffloadState: "hw",
		HwPkts:       42000,
	}
	b, err := json.Marshal(lb)
	if err != nil {
		t.Fatalf("json.Marshal: %v", err)
	}
	var m map[string]interface{}
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatalf("json.Unmarshal: %v", err)
	}
	if v, ok := m["offload_state"]; !ok || v != "hw" {
		t.Errorf("offload_state: want %q, got %v (present=%v)", "hw", v, ok)
	}
	if v, ok := m["hw_pkts"]; !ok {
		t.Errorf("hw_pkts: want 42000, got absent")
	} else if v.(float64) != 42000 {
		t.Errorf("hw_pkts: want 42000, got %v", v)
	}
}

// TestLbModelOffloadFieldsOmitted verifies LoadBalancerModel OffloadState + HwPkts
// are absent when zero — non-DOCA backward-compat.
func TestLbModelOffloadFieldsOmitted(t *testing.T) {
	lb := LoadBalancerModel{}
	b, err := json.Marshal(lb)
	if err != nil {
		t.Fatalf("json.Marshal: %v", err)
	}
	var m map[string]interface{}
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatalf("json.Unmarshal: %v", err)
	}
	if _, ok := m["offload_state"]; ok {
		t.Errorf("offload_state should be absent (omitempty) when empty, but found in JSON")
	}
	if _, ok := m["hw_pkts"]; ok {
		t.Errorf("hw_pkts should be absent (omitempty) when 0, but found in JSON")
	}
}
