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
	"strings"
	"time"

	"github.com/spf13/cobra"
)

type CreateSYNFloodOptions struct {
	SYNThreshold    uint32
	CookieThreshold uint32
	WhitelistIPs    string
}

func NewCreateSYNFloodCmd(restOptions *api.RESTOptions) *cobra.Command {
	o := CreateSYNFloodOptions{}

	var createSYNFloodCmd = &cobra.Command{
		Use:   "synflood --synThreshold=<num> --cookieThreshold=<num> [--whitelistIps=<IP1,IP2,...>]",
		Short: "Enable and configure SYN flood protection",
		Long: `Enable and configure SYN flood protection using LoxiLB

SYN flood protection provides XDP-layer defense against SYN flood DDoS attacks.
When enabled, the system monitors incoming SYN packet rates and activates
SYN cookies when thresholds are exceeded.

Arguments:
  --synThreshold      Maximum SYN packets per second before blocking (required)
                      Must be greater than cookieThreshold
                      Example: 100 = block at 100 SYNs/sec
  
  --cookieThreshold   SYN rate to activate SYN cookies (required)
                      Must be less than synThreshold
                      Example: 50 = activate cookies at 50 SYNs/sec
  
  --whitelistIps      Comma-separated list of whitelisted IPs (optional)
                      IPs in CIDR notation that bypass rate limiting
                      Example: "10.0.0.1/32,192.168.1.0/24"

Validation Rules:
  - cookieThreshold < synThreshold (enforced by API)
  - synThreshold > 0 (enforced by API)
  - IP addresses must be valid CIDR notation

Examples:
  # Basic protection (100 SYNs/sec max, cookies at 50 SYNs/sec)
  loxicmd create synflood --synThreshold=100 --cookieThreshold=50

  # With whitelisted IPs (trusted sources)
  loxicmd create synflood --synThreshold=200 --cookieThreshold=100 \
    --whitelistIps="10.0.0.1/32,192.168.1.0/24"

  # Strict protection (low thresholds for sensitive services)
  loxicmd create synflood --synThreshold=50 --cookieThreshold=20

  # Lenient protection (high thresholds for high-traffic sites)
  loxicmd create synflood --synThreshold=1000 --cookieThreshold=500

Use Cases:
  - DDoS mitigation: Automatically drop excessive SYN packets
  - SYN flood attacks: Activate SYN cookies to validate clients
  - Whitelist trusted networks: Allow monitoring/management IPs
  - Rate limiting: Control new connection establishment rate

Performance:
  - XDP-layer filtering provides <1µs overhead per packet
  - Suitable for high-throughput environments (10Gbps+)
  - Statistics updated atomically without performance impact
`,
		Aliases: []string{"SYNFlood", "synf", "syn-flood"},
		PreRun: func(cmd *cobra.Command, args []string) {
			if o.SYNThreshold == 0 || o.CookieThreshold == 0 {
				cmd.Help()
				os.Exit(0)
			}
		},
		Run: func(cmd *cobra.Command, args []string) {
			// Validate thresholds locally (API will also validate)
			if o.CookieThreshold >= o.SYNThreshold {
				fmt.Printf("Error: cookieThreshold (%d) must be less than synThreshold (%d)\n",
					o.CookieThreshold, o.SYNThreshold)
				return
			}

			// Parse whitelist IPs (comma-separated)
			var whitelistIPs []string
			if o.WhitelistIPs != "" {
				whitelistIPs = strings.Split(o.WhitelistIPs, ",")
				// Trim whitespace from each IP
				for i := range whitelistIPs {
					whitelistIPs[i] = strings.TrimSpace(whitelistIPs[i])
				}
			}

			// Create SYNFloodConfig
			var synFloodConfig api.SYNFloodConfig
			synFloodConfig.Enabled = true
			synFloodConfig.SYNThreshold = o.SYNThreshold
			synFloodConfig.CookieThreshold = o.CookieThreshold
			synFloodConfig.WhitelistIPs = whitelistIPs

			resp, err := SYNFloodAPICall(restOptions, synFloodConfig)
			if err != nil {
				fmt.Printf("Error: %s\n", err.Error())
				return
			}
			defer resp.Body.Close()

			fmt.Printf("Debug: response.StatusCode: %d\n", resp.StatusCode)
			if resp.StatusCode == http.StatusOK || resp.StatusCode == http.StatusNoContent {
				fmt.Printf("✅ SYN flood protection enabled successfully\n")
				fmt.Printf("   SYN threshold: %d packets/sec\n", o.SYNThreshold)
				fmt.Printf("   Cookie threshold: %d packets/sec\n", o.CookieThreshold)
				if len(whitelistIPs) > 0 {
					fmt.Printf("   Whitelisted IPs: %s\n", strings.Join(whitelistIPs, ", "))
				}
				return
			} else {
				PrintCreateResult(resp, *restOptions)
			}
		},
	}

	createSYNFloodCmd.Flags().Uint32Var(&o.SYNThreshold, "synThreshold", 0, "Maximum SYN packets per second (required)")
	createSYNFloodCmd.Flags().Uint32Var(&o.CookieThreshold, "cookieThreshold", 0, "Threshold to activate SYN cookies (required)")
	createSYNFloodCmd.Flags().StringVar(&o.WhitelistIPs, "whitelistIps", "", "Comma-separated whitelisted IPs in CIDR notation")

	createSYNFloodCmd.MarkFlagRequired("synThreshold")
	createSYNFloodCmd.MarkFlagRequired("cookieThreshold")

	return createSYNFloodCmd
}

func SYNFloodAPICall(restOptions *api.RESTOptions, synFloodConfig api.SYNFloodConfig) (*http.Response, error) {
	client := api.NewLoxiClient(restOptions)
	ctx := context.TODO()
	var cancel context.CancelFunc
	if restOptions.Timeout > 0 {
		ctx, cancel = context.WithTimeout(context.TODO(), time.Duration(restOptions.Timeout)*time.Second)
		defer cancel()
	}

	return client.SYNFlood().Create(ctx, synFloodConfig)
}
