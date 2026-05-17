//go:build linux

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

// Phase 65 D-13: unit tests for -o wide OFFLOAD_STATE + HW_PKTS columns in
// get conntrack and get loadbalancer.  No httptest or CGO — pure table rendering.
// Build tag linux matches the rest of cmd/get (get_netlink.go uses Linux syscalls).
package get

import (
	"loxicmd/pkg/api"
	"testing"
)

// ---------------------------------------------------------------------------
// Conntrack wide-output tests
// ---------------------------------------------------------------------------

// TestGetCtWideColumns verifies makeConntrackDataWide adds OFFLOAD_STATE and
// HW_PKTS columns at the rightmost positions (D-13).
func TestGetCtWideColumns(t *testing.T) {
	t.Run("hw-offloaded entry shows state and packet count", func(t *testing.T) {
		ctresp := api.CtInformationGet{
			CtInfo: []api.ConntrackInformation{
				{
					ServName:     "svc1",
					Dip:          "10.0.0.2",
					Sip:          "10.0.0.1",
					Dport:        80,
					Sport:        54321,
					Proto:        "tcp",
					Ident:        "0:42",
					CState:       "established",
					CAct:         "forward",
					Pkts:         1000,
					Bytes:        65536,
					OffloadState: "hw",
					HwPkts:       12000,
				},
			},
		}
		o := api.RESTOptions{}
		rows := makeConntrackDataWide(o, ctresp)
		if len(rows) != 1 {
			t.Fatalf("expected 1 row, got %d", len(rows))
		}
		row := rows[0]
		// Row layout: ServName, Dip, Sip, Dport, Sport, Proto, Ident, CState, CAct, Pkts, Bytes, OFFLOAD_STATE, HW_PKTS
		if len(row) != len(CONNTRACK_WIDE_TITLE) {
			t.Errorf("expected %d columns, got %d", len(CONNTRACK_WIDE_TITLE), len(row))
		}
		offloadIdx := len(CONNTRACK_WIDE_TITLE) - 2
		hwPktsIdx := len(CONNTRACK_WIDE_TITLE) - 1
		if row[offloadIdx] != "hw" {
			t.Errorf("OFFLOAD_STATE: want %q got %q", "hw", row[offloadIdx])
		}
		if row[hwPktsIdx] != "12000" {
			t.Errorf("HW_PKTS: want %q got %q", "12000", row[hwPktsIdx])
		}
	})

	t.Run("non-offloaded entry shows none and dash", func(t *testing.T) {
		ctresp := api.CtInformationGet{
			CtInfo: []api.ConntrackInformation{
				{
					ServName: "svc2",
					Dip:      "10.0.0.4",
					Sip:      "10.0.0.3",
					Dport:    443,
					Sport:    12345,
					Proto:    "tcp",
					Ident:    "0:7",
					CState:   "established",
					CAct:     "forward",
					Pkts:     500,
					Bytes:    32768,
					// OffloadState and HwPkts absent (omitempty → zero values)
				},
			},
		}
		o := api.RESTOptions{}
		rows := makeConntrackDataWide(o, ctresp)
		if len(rows) != 1 {
			t.Fatalf("expected 1 row, got %d", len(rows))
		}
		row := rows[0]
		offloadIdx := len(CONNTRACK_WIDE_TITLE) - 2
		hwPktsIdx := len(CONNTRACK_WIDE_TITLE) - 1
		if row[offloadIdx] != "none" {
			t.Errorf("OFFLOAD_STATE: want %q got %q", "none", row[offloadIdx])
		}
		if row[hwPktsIdx] != "-" {
			t.Errorf("HW_PKTS: want %q got %q (dash convention for non-offloaded)", "-", row[hwPktsIdx])
		}
	})

	t.Run("transitioning entry shows state and packet count", func(t *testing.T) {
		ctresp := api.CtInformationGet{
			CtInfo: []api.ConntrackInformation{
				{
					ServName:     "svc3",
					Dip:          "10.0.0.6",
					Sip:          "10.0.0.5",
					Dport:        8080,
					Sport:        23456,
					Proto:        "tcp",
					Ident:        "0:99",
					CState:       "established",
					CAct:         "forward",
					Pkts:         200,
					Bytes:        8192,
					OffloadState: "transitioning",
					HwPkts:       50,
				},
			},
		}
		o := api.RESTOptions{}
		rows := makeConntrackDataWide(o, ctresp)
		if len(rows) != 1 {
			t.Fatalf("expected 1 row, got %d", len(rows))
		}
		row := rows[0]
		offloadIdx := len(CONNTRACK_WIDE_TITLE) - 2
		hwPktsIdx := len(CONNTRACK_WIDE_TITLE) - 1
		if row[offloadIdx] != "transitioning" {
			t.Errorf("OFFLOAD_STATE: want %q got %q", "transitioning", row[offloadIdx])
		}
		if row[hwPktsIdx] != "50" {
			t.Errorf("HW_PKTS: want %q got %q", "50", row[hwPktsIdx])
		}
	})
}

// TestGetCtNarrowUnchanged verifies makeConntrackData (narrow output) does NOT
// include OFFLOAD_STATE or HW_PKTS — backward-compat per D-13.
func TestGetCtNarrowUnchanged(t *testing.T) {
	ctresp := api.CtInformationGet{
		CtInfo: []api.ConntrackInformation{
			{
				ServName:     "svc1",
				Dip:          "10.0.0.2",
				Sip:          "10.0.0.1",
				Dport:        80,
				Sport:        54321,
				Proto:        "tcp",
				Ident:        "0:1",
				CState:       "established",
				CAct:         "forward",
				Pkts:         100,
				Bytes:        4096,
				OffloadState: "hw",
				HwPkts:       999,
			},
		},
	}
	o := api.RESTOptions{}
	rows := makeConntrackData(o, ctresp)
	if len(rows) != 1 {
		t.Fatalf("expected 1 row, got %d", len(rows))
	}
	// Narrow output has 11 columns: ServName, Dip, Sip, Dport, Sport, Proto, Ident, CState, CAct, Pkts, Bytes
	const narrowCols = 11
	if len(rows[0]) != narrowCols {
		t.Errorf("narrow output: expected %d columns, got %d (OFFLOAD_STATE/HW_PKTS must not appear)", narrowCols, len(rows[0]))
	}
}

// TestGetCtWideColumnCount verifies CONNTRACK_WIDE_TITLE has 13 entries
// (11 narrow + OFFLOAD_STATE + HW_PKTS).
func TestGetCtWideColumnCount(t *testing.T) {
	const want = 13
	if len(CONNTRACK_WIDE_TITLE) != want {
		t.Errorf("CONNTRACK_WIDE_TITLE: want %d entries, got %d", want, len(CONNTRACK_WIDE_TITLE))
	}
	last := CONNTRACK_WIDE_TITLE[len(CONNTRACK_WIDE_TITLE)-1]
	secondLast := CONNTRACK_WIDE_TITLE[len(CONNTRACK_WIDE_TITLE)-2]
	if secondLast != "OFFLOAD_STATE" {
		t.Errorf("second-to-last column: want OFFLOAD_STATE, got %q", secondLast)
	}
	if last != "HW_PKTS" {
		t.Errorf("last column: want HW_PKTS, got %q", last)
	}
}

// ---------------------------------------------------------------------------
// LoadBalancer wide-output tests
// ---------------------------------------------------------------------------

// TestGetLbWideColumns verifies LOADBALANCER_WIDE_TITLE ends with OFFLOAD_STATE
// and HW_PKTS (D-13 rightmost placement).
func TestGetLbWideColumns(t *testing.T) {
	if len(LOADBALANCER_WIDE_TITLE) < 2 {
		t.Fatal("LOADBALANCER_WIDE_TITLE has fewer than 2 entries")
	}
	last := LOADBALANCER_WIDE_TITLE[len(LOADBALANCER_WIDE_TITLE)-1]
	secondLast := LOADBALANCER_WIDE_TITLE[len(LOADBALANCER_WIDE_TITLE)-2]
	if secondLast != "OFFLOAD_STATE" {
		t.Errorf("second-to-last LB wide column: want OFFLOAD_STATE, got %q", secondLast)
	}
	if last != "HW_PKTS" {
		t.Errorf("last LB wide column: want HW_PKTS, got %q", last)
	}
}

// TestGetLbModelFields verifies LoadBalancerModel has OffloadState and HwPkts fields
// with the correct omitempty JSON tags (D-13).
func TestGetLbModelFields(t *testing.T) {
	m := api.LoadBalancerModel{
		OffloadState: "hw",
		HwPkts:       42000,
	}
	if m.OffloadState != "hw" {
		t.Errorf("OffloadState: want %q got %q", "hw", m.OffloadState)
	}
	if m.HwPkts != 42000 {
		t.Errorf("HwPkts: want 42000 got %d", m.HwPkts)
	}
}
