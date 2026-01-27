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
		Long:  `Display L4 connection tracing configuration and statistics. status, stats, connections. If no sub-command is specified, all information will be displayed.`,
		Run: func(cmd *cobra.Command, args []string) {
			client := api.NewLoxiClient(restOptions)
			ctx := context.TODO()
			resp, err := client.L4Trace().Get(ctx)
			if err != nil {
				fmt.Printf("Error: %s\n", err.Error())
				return
			}
			if resp.StatusCode == http.StatusOK {
				PrintGetL4TraceStatusResult(resp, restOptions.PrintOption)
				PrintGetL4TraceStatsResult(resp, restOptions.PrintOption)
				PrintGetL4TraceConnectionResult(resp, restOptions.PrintOption)
				return
			}
		},
	}
	GetL4TraceCmd.AddCommand(NewGetL4TraceStatusCmd(restOptions))
	GetL4TraceCmd.AddCommand(NewGetL4TraceStatsCmd(restOptions))
	GetL4TraceCmd.AddCommand(NewGetL4TraceConnectionsCmd(restOptions))

	return GetL4TraceCmd
}

func NewGetL4TraceStatusCmd(restOptions *api.RESTOptions) *cobra.Command {
	var GetL4TraceStatusCmd = &cobra.Command{
		Use:   "status",
		Short: "Get L4 connection tracing status",
		Long:  `Display L4 connection tracing configuration status.`,
		Run: func(cmd *cobra.Command, args []string) {
			client := api.NewLoxiClient(restOptions)
			ctx := context.TODO()
			resp, err := client.L4Trace().Get(ctx)
			if err != nil {
				fmt.Printf("Error: %s\n", err.Error())
				return
			}
			if resp.StatusCode == http.StatusOK {
				PrintGetL4TraceStatusResult(resp, restOptions.PrintOption)
				return
			}
		},
	}
	return GetL4TraceStatusCmd
}

func NewGetL4TraceStatsCmd(restOptions *api.RESTOptions) *cobra.Command {
	var GetL4TraceStatsCmd = &cobra.Command{
		Use:   "stats",
		Short: "Get L4 connection tracing statistics",
		Long:  `Display L4 connection tracing statistics.`,
		Run: func(cmd *cobra.Command, args []string) {
			client := api.NewLoxiClient(restOptions)
			ctx := context.TODO()
			resp, err := client.L4Trace().Get(ctx)
			if err != nil {
				fmt.Printf("Error: %s\n", err.Error())
				return
			}
			if resp.StatusCode == http.StatusOK {
				PrintGetL4TraceStatsResult(resp, restOptions.PrintOption)
				return
			}
		},
	}
	return GetL4TraceStatsCmd
}

func NewGetL4TraceConnectionsCmd(restOptions *api.RESTOptions) *cobra.Command {
	var GetL4TraceConnectionsCmd = &cobra.Command{
		Use:   "connections",
		Short: "Get L4 connection tracing connection statistics",
		Long:  `Display L4 connection tracing connection statistics.`,
		Run: func(cmd *cobra.Command, args []string) {
			client := api.NewLoxiClient(restOptions)
			ctx := context.TODO()
			resp, err := client.L4Trace().Get(ctx)
			if err != nil {
				fmt.Printf("Error: %s\n", err.Error())
				return
			}
			if resp.StatusCode == http.StatusOK {
				PrintGetL4TraceConnectionResult(resp, restOptions.PrintOption)
				return
			}
		},
	}
	return GetL4TraceConnectionsCmd
}

func PrintGetL4TraceStatusResult(resp *api.RESTResponse, printOption string) {
	if resp.Result == nil {
		fmt.Println("No L4 trace status available")
		return
	}

	status, ok := resp.Result.(L4TraceStatusModel)
	if !ok {
		fmt.Println("Error: Invalid response format")
		return
	}
	// Prepare data for table display
	var data [][]string
	// Table Init
	table := TableInit()

	table.SetHeader(TRACING_STATUS_TITLE)
	data = append(data, []string{fmt.Sprintf("%v", status.Enabled), fmt.Sprintf("%d", status.SamplingRate), fmt.Sprintf("%d", status.ConfigVersion)})
	// Rendering the load balance data to table
	TableShow(data, table)
}

func PrintGetL4TraceStatsResult(resp *api.RESTResponse, printOption string) {
	if resp.Result == nil {
		fmt.Println("No L4 trace status available")
		return
	}

	status, ok := resp.Result.(L4TraceStatusModel)
	if !ok {
		fmt.Println("Error: Invalid response format")
		return
	}
	// Prepare data for table display
	var data [][]string
	// Table Init
	table := TableInit()

	table.SetHeader(TRACING_STATISTICS_TITLE)
	data = append(data, []string{fmt.Sprintf("%v", status.Stats.TotalEvents), fmt.Sprintf("%d", status.Stats.SampledEvents), fmt.Sprintf("%d", status.Stats.DroppedEvents), fmt.Sprintf("%d", status.Stats.TCPEvents), fmt.Sprintf("%d", status.Stats.SctpEvents)})

	// Rendering the load balance data to table
	TableShow(data, table)
}

func PrintGetL4TraceConnectionResult(resp *api.RESTResponse, printOption string) {
	if resp.Result == nil {
		fmt.Println("No L4 trace status available")
		return
	}

	status, ok := resp.Result.(L4TraceStatusModel)
	if !ok {
		fmt.Println("Error: Invalid response format")
		return
	}

	// Prepare data for table display
	var data [][]string
	// Table Init
	table := TableInit()
	table.SetHeader(TRACING_CONNECTION_TITLE)
	data = append(data, []string{fmt.Sprintf("%d", status.Stats.ConnNew), fmt.Sprintf("%d", status.Stats.ConnEstablished), fmt.Sprintf("%d", status.Stats.ConnClosed), fmt.Sprintf("%d", status.Stats.ConnTimeout), fmt.Sprintf("%d", status.Stats.ConnReset), fmt.Sprintf("%d", status.Stats.ConnError)})
	// Rendering the load balance data to table
	TableShow(data, table)
}
