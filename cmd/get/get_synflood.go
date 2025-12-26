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
package get

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"loxicmd/pkg/api"
	"net/http"
	"strings"
	"time"

	"github.com/spf13/cobra"
)

func NewGetSYNFloodCmd(restOptions *api.RESTOptions) *cobra.Command {
	var GetSYNFloodCmd = &cobra.Command{
		Use:     "synflood",
		Short:   "Get SYN flood protection configuration and statistics",
		Aliases: []string{"SYNFlood", "synf", "syn-flood"},
		Long: `Display SYN flood protection configuration and real-time statistics

This command shows:
  - Current protection status (enabled/disabled)
  - Configured thresholds (SYN and cookie)
  - Whitelisted IP addresses
  - Real-time statistics:
    * Total SYN packets processed
    * Number of blocked SYNs
    * Number of passed SYNs
    * SYN cookie activations
    * Unique source IPs detected

Output Formats:
  - Table format (default): Human-readable tabular display
  - JSON format (--print json): Machine-readable JSON output

Examples:
  # Get current configuration and statistics
  loxicmd get synflood

  # Get output in JSON format
  loxicmd get synflood --print json

  # Monitor statistics in real-time (with watch)
  watch -n 1 'loxicmd get synflood'
`,
		Run: func(cmd *cobra.Command, args []string) {
			client := api.NewLoxiClient(restOptions)
			ctx := context.TODO()
			var cancel context.CancelFunc
			if restOptions.Timeout > 0 {
				ctx, cancel = context.WithTimeout(context.TODO(), time.Duration(restOptions.Timeout)*time.Second)
				defer cancel()
			}
			resp, err := client.SYNFlood().SetUrl("/config/synflood/all").Get(ctx)
			if err != nil {
				fmt.Printf("Error: %s\n", err.Error())
				return
			}
			if resp.StatusCode == http.StatusOK {
				PrintGetSYNFloodResult(resp, *restOptions)
				return
			} else {
				fmt.Printf("Error: Unexpected status code %d\n", resp.StatusCode)
			}
		},
	}

	return GetSYNFloodCmd
}

func PrintGetSYNFloodResult(resp *http.Response, o api.RESTOptions) {
	synfresp := api.SYNFloodInformationGet{}
	var data [][]string
	resultByte, err := io.ReadAll(resp.Body)
	if err != nil {
		fmt.Printf("Error: Failed to read HTTP response: (%s)\n", err.Error())
		return
	}

	if err := json.Unmarshal(resultByte, &synfresp); err != nil {
		fmt.Printf("Error: Failed to unmarshal HTTP response: (%s)\n", err.Error())
		return
	}

	// if json options enable, it print as a json format.
	if o.PrintOption == "json" {
		resultIndent, _ := json.MarshalIndent(synfresp, "", "    ")
		fmt.Println(string(resultIndent))
		return
	}

	// Table Init
	table := TableInit()

	// Table header
	table.SetHeader(SYNFLOOD_TITLE)

	// Making SYN flood data
	for _, entry := range synfresp.SYNFloodInfo {
		// Format enabled status
		enabledStr := "disabled"
		if entry.Enabled {
			enabledStr = "enabled"
		}

		// Format whitelist IPs
		whitelistStr := "-"
		if len(entry.WhitelistIPs) > 0 {
			whitelistStr = strings.Join(entry.WhitelistIPs, ", ")
		}

		data = append(data, []string{
			enabledStr,
			fmt.Sprintf("%d", entry.SYNThreshold),
			fmt.Sprintf("%d", entry.CookieThreshold),
			whitelistStr,
			fmt.Sprintf("%d", entry.TotalSYNs),
			fmt.Sprintf("%d", entry.BlockedSYNs),
			fmt.Sprintf("%d", entry.PassedSYNs),
			fmt.Sprintf("%d", entry.CookieActivations),
			fmt.Sprintf("%d", entry.UniqueIPs),
		})
	}

	// If no data, show disabled state
	if len(data) == 0 {
		data = append(data, []string{
			"disabled",
			"-",
			"-",
			"-",
			"0",
			"0",
			"0",
			"0",
			"0",
		})
	}

	// Rendering the SYN flood data to table
	TableShow(data, table)
}

func SYNFloodAPICall(restOptions *api.RESTOptions) (*http.Response, error) {
	client := api.NewLoxiClient(restOptions)
	ctx := context.TODO()
	var cancel context.CancelFunc
	if restOptions.Timeout > 0 {
		ctx, cancel = context.WithTimeout(context.TODO(), time.Duration(restOptions.Timeout)*time.Second)
		defer cancel()
	}
	resp, err := client.SYNFlood().SetUrl("/config/synflood/all").Get(ctx)
	if err != nil {
		fmt.Printf("Error: %s\n", err.Error())
		return nil, err
	}
	return resp, nil
}
