/*
 * Copyright (c) 2024-2025 LoxiLB Authors
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

package get

import (
	"context"
	"fmt"
	"loxicmd/pkg/api"
	"net/http"

	"github.com/spf13/cobra"
)

type L4TraceStatusModel struct {
	Enabled       bool              `json:"enabled"`
	SamplingRate  int64             `json:"sampling_rate"`
	ConfigVersion int64             `json:"config_version"`
	Stats         L4TraceStatsModel `json:"stats"`
}

type L4TraceStatsModel struct {
	TotalEvents     int64 `json:"total_events"`
	SampledEvents   int64 `json:"sampled_events"`
	DroppedEvents   int64 `json:"dropped_events"`
	TCPEvents       int64 `json:"tcp_events"`
	SctpEvents      int64 `json:"sctp_events"`
	ConnNew         int64 `json:"conn_new"`
	ConnEstablished int64 `json:"conn_established"`
	ConnClosed      int64 `json:"conn_closed"`
	ConnTimeout     int64 `json:"conn_timeout"`
	ConnReset       int64 `json:"conn_reset"`
	ConnError       int64 `json:"conn_error"`
}

func NewGetL4TraceCmd(restOptions *api.RESTOptions) *cobra.Command {
	var GetL4TraceCmd = &cobra.Command{
		Use:   "l4trace",
		Short: "Get L4 connection tracing status",
		Long:  `Display L4 connection tracing configuration and statistics`,
		Run: func(cmd *cobra.Command, args []string) {
			client := api.NewLoxiClient(restOptions)
			ctx := context.TODO()
			resp, err := client.L4Trace().Get(ctx)
			if err != nil {
				fmt.Printf("Error: %s\n", err.Error())
				return
			}
			if resp.StatusCode == http.StatusOK {
				PrintGetL4TraceResult(resp, restOptions.PrintOption)
				return
			}
		},
	}

	return GetL4TraceCmd
}

func PrintGetL4TraceResult(resp *api.RESTResponse, printOption string) {
	if resp.Result == nil {
		fmt.Println("No L4 trace status available")
		return
	}

	status, ok := resp.Result.(L4TraceStatusModel)
	if !ok {
		fmt.Println("Error: Invalid response format")
		return
	}

	// Print in human-readable format
	fmt.Println("=== L4 Connection Tracing Status ===")
	fmt.Printf("Enabled:         %v\n", status.Enabled)
	fmt.Printf("Sampling Rate:   %d%%\n", status.SamplingRate)
	fmt.Printf("Config Version:  %d\n", status.ConfigVersion)
	fmt.Println("\n=== Statistics ===")
	fmt.Printf("Total Events:    %d\n", status.Stats.TotalEvents)
	fmt.Printf("Sampled Events:  %d\n", status.Stats.SampledEvents)
	fmt.Printf("Dropped Events:  %d\n", status.Stats.DroppedEvents)
	fmt.Printf("TCP Events:      %d\n", status.Stats.TCPEvents)
	fmt.Printf("SCTP Events:     %d\n", status.Stats.SctpEvents)
	fmt.Println("\n=== Connection Lifecycle ===")
	fmt.Printf("New:             %d\n", status.Stats.ConnNew)
	fmt.Printf("Established:     %d\n", status.Stats.ConnEstablished)
	fmt.Printf("Closed (Clean):  %d\n", status.Stats.ConnClosed)
	fmt.Printf("Closed (Timeout):%d\n", status.Stats.ConnTimeout)
	fmt.Printf("Closed (Reset):  %d\n", status.Stats.ConnReset)
	fmt.Printf("Errors:          %d\n", status.Stats.ConnError)
}
