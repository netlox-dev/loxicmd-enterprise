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
package create

import (
	"context"
	"fmt"
	"loxicmd/pkg/api"
	"net/http"
	"os"
	"time"

	"github.com/spf13/cobra"
)

type CreateIPFilterOptions struct {
	IPPrefix   string
	Action     string
	FilterType string
	Zone       uint16
	Priority   uint16
}

func NewCreateIPFilterCmd(restOptions *api.RESTOptions) *cobra.Command {
	o := CreateIPFilterOptions{}

	var createIPFilterCmd = &cobra.Command{
		Use:   "ipfilter --ipPrefix=<CIDR> --action=<allow|drop> --filterType=<whitelist|blacklist> [--zone=<zone>] [--priority=<priority>]",
		Short: "Create an IP Filter rule",
		Long: `Create an IP whitelist/blacklist rule using LoxiLB

IP Filter provides XDP-layer IP filtering for DDoS protection with CIDR support.
Rules are applied at the XDP layer before sk_buff allocation for <1µs overhead.

Arguments:
  --ipPrefix      IP address in CIDR notation (required)
                  Examples: "192.168.1.0/24", "10.0.0.5/32", "2001:db8::/32"
  
  --action        Filter action (required)
                  - "allow": Permit the traffic
                  - "drop":  Block the traffic
  
  --filterType    Map type (required)
                  - "whitelist": Add to whitelist (typically with action="allow")
                  - "blacklist": Add to blacklist (typically with action="drop")
  
  --zone          Security zone (optional, default: 0 = all zones)
                  0 = Apply to all traffic
                  >0 = Apply only to specific zone
  
  --priority      Rule priority (optional, default: 100)
                  Higher values = higher priority
                  Range: 1-65535

Examples:
  # Block a single IP (add to blacklist)
  loxicmd create ipfilter --ipPrefix="192.168.1.100/32" --action="drop" --filterType="blacklist"
  
  # Block an entire subnet with high priority
  loxicmd create ipfilter --ipPrefix="10.0.0.0/24" --action="drop" --filterType="blacklist" --priority=200
  
  # Whitelist a specific IP with high priority
  loxicmd create ipfilter --ipPrefix="172.31.35.197/32" --action="allow" --filterType="whitelist" --priority=1000
  
  # Block IPv6 range
  loxicmd create ipfilter --ipPrefix="2001:db8::/32" --action="drop" --filterType="blacklist"
  
  # Zone-specific rule
  loxicmd create ipfilter --ipPrefix="192.168.1.0/24" --action="drop" --filterType="blacklist" --zone=10
`,
		Aliases: []string{"IPFilter", "ipf", "ip-filter"},
		PreRun: func(cmd *cobra.Command, args []string) {
			if o.IPPrefix == "" || o.Action == "" || o.FilterType == "" {
				cmd.Help()
				os.Exit(0)
			}
		},
		Run: func(cmd *cobra.Command, args []string) {
			// Validate action
			if o.Action != "allow" && o.Action != "drop" {
				fmt.Printf("Error: Invalid action '%s'. Must be 'allow' or 'drop'\n", o.Action)
				return
			}

			// Validate filterType
			if o.FilterType != "whitelist" && o.FilterType != "blacklist" {
				fmt.Printf("Error: Invalid filterType '%s'. Must be 'whitelist' or 'blacklist'\n", o.FilterType)
				return
			}

			// Create IPFilterMod
			var ipFilterMod api.IPFilterMod
			ipFilterMod.IPPrefix = o.IPPrefix
			ipFilterMod.Action = o.Action
			ipFilterMod.FilterType = o.FilterType
			ipFilterMod.Zone = o.Zone
			ipFilterMod.Priority = o.Priority

			resp, err := IPFilterAPICall(restOptions, ipFilterMod)
			if err != nil {
				fmt.Printf("Error: %s\n", err.Error())
				return
			}
			defer resp.Body.Close()

			fmt.Printf("Debug: response.StatusCode: %d\n", resp.StatusCode)
			if resp.StatusCode == http.StatusOK {
				PrintCreateResult(resp, *restOptions)
				return
			}
		},
	}

	createIPFilterCmd.Flags().StringVar(&o.IPPrefix, "ipPrefix", "", "IP address in CIDR notation (required)")
	createIPFilterCmd.Flags().StringVar(&o.Action, "action", "", "Filter action: allow or drop (required)")
	createIPFilterCmd.Flags().StringVar(&o.FilterType, "filterType", "", "Map type: whitelist or blacklist (required)")
	createIPFilterCmd.Flags().Uint16Var(&o.Zone, "zone", 0, "Security zone (0=all zones)")
	createIPFilterCmd.Flags().Uint16Var(&o.Priority, "priority", 100, "Rule priority (higher=more important)")

	createIPFilterCmd.MarkFlagRequired("ipPrefix")
	createIPFilterCmd.MarkFlagRequired("action")
	createIPFilterCmd.MarkFlagRequired("filterType")

	return createIPFilterCmd
}

func IPFilterAPICall(restOptions *api.RESTOptions, ipFilterModel api.IPFilterMod) (*http.Response, error) {
	client := api.NewLoxiClient(restOptions)
	ctx := context.TODO()
	var cancel context.CancelFunc
	if restOptions.Timeout > 0 {
		ctx, cancel = context.WithTimeout(context.TODO(), time.Duration(restOptions.Timeout)*time.Second)
		defer cancel()
	}

	return client.IPFilter().Create(ctx, ipFilterModel)
}
