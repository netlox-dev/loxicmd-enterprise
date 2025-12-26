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
package delete

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"time"

	"loxicmd/pkg/api"

	"github.com/spf13/cobra"
)

type DeleteIPFilterOptions struct {
	IPPrefix string
	MapType  string
}

func NewDeleteIPFilterCmd(restOptions *api.RESTOptions) *cobra.Command {
	o := DeleteIPFilterOptions{}

	var deleteIPFilterCmd = &cobra.Command{
		Use:   "ipfilter --ipPrefix=<CIDR> --mapType=<blacklist|whitelist>",
		Short: "Delete an IP Filter rule",
		Long: `Delete an IP whitelist/blacklist rule from LoxiLB

Arguments:
  --ipPrefix      IP address in CIDR notation (required)
                  Examples: "192.168.1.0/24", "10.0.0.5/32"
  
  --mapType       Map type to delete from (required)
                  - "blacklist": Remove from blacklist (drop rules)
                  - "whitelist": Remove from whitelist (allow rules)

Examples:
  # Delete blacklist rule
  loxicmd delete ipfilter --ipPrefix="192.168.1.100/32" --mapType="blacklist"
  
  # Delete whitelist rule
  loxicmd delete ipfilter --ipPrefix="10.0.0.0/24" --mapType="whitelist"
  
  # Delete IPv6 rule
  loxicmd delete ipfilter --ipPrefix="2001:db8::/32" --mapType="blacklist"
`,
		Aliases: []string{"IPFilter", "ipf", "ip-filter"},
		PreRun: func(cmd *cobra.Command, args []string) {
			if o.IPPrefix == "" || o.MapType == "" {
				cmd.Help()
				os.Exit(0)
			}
		},
		Run: func(cmd *cobra.Command, args []string) {
			// Validate mapType
			if o.MapType != "blacklist" && o.MapType != "whitelist" {
				fmt.Printf("Error: Invalid mapType '%s'. Must be 'blacklist' or 'whitelist'\n", o.MapType)
				return
			}

			client := api.NewLoxiClient(restOptions)
			ctx := context.TODO()
			var cancel context.CancelFunc
			if restOptions.Timeout > 0 {
				ctx, cancel = context.WithTimeout(ctx, time.Duration(restOptions.Timeout)*time.Second)
				defer cancel()
			}

			query, err := MakeIPFilterDeleteQuery(o.IPPrefix, o.MapType)
			if err != nil {
				fmt.Printf("Error: Failed to delete IP Filter: %s\n", err.Error())
				return
			}

			resp, err := client.IPFilter().Query(query).Delete(ctx)
			if err != nil {
				fmt.Printf("Error: Failed to delete IP Filter: %s\n", err.Error())
				return
			}
			defer resp.Body.Close()

			fmt.Printf("Debug: response.StatusCode: %d\n", resp.StatusCode)
			if resp.StatusCode == http.StatusOK {
				PrintDeleteResult(resp, *restOptions)
				return
			}
		},
	}

	deleteIPFilterCmd.Flags().StringVar(&o.IPPrefix, "ipPrefix", "", "IP address in CIDR notation (required)")
	deleteIPFilterCmd.Flags().StringVar(&o.MapType, "mapType", "", "Map type: blacklist or whitelist (required)")

	deleteIPFilterCmd.MarkFlagRequired("ipPrefix")
	deleteIPFilterCmd.MarkFlagRequired("mapType")

	return deleteIPFilterCmd
}

func MakeIPFilterDeleteQuery(ipPrefix, mapType string) (map[string]string, error) {
	query := map[string]string{
		"cidr":       ipPrefix,
		"filterType": mapType,
	}
	return query, nil
}
