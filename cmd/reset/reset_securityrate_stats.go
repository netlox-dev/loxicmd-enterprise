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
package reset

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"loxicmd/pkg/api"

	"github.com/spf13/cobra"
)

func NewResetSecurityRateStatsCmd(restOptions *api.RESTOptions) *cobra.Command {
	var cmd = &cobra.Command{
		Use:     "securityrate",
		Aliases: []string{"securityrate-stats"},
		Short:   "Reset security rate statistics",
		Long:    "Reset all accumulated security rate limiting statistics (SYN flood, connection rate, UDP flood) to zero",
		Run: func(cmd *cobra.Command, args []string) {
			client := api.NewLoxiClient(restOptions)
			ctx := context.TODO()
			var cancel context.CancelFunc
			if restOptions.Timeout > 0 {
				ctx, cancel = context.WithTimeout(ctx, time.Duration(restOptions.Timeout)*time.Second)
				defer cancel()
			}

			// Use SubResources to append "reset" to the URL path
			resp, err := client.SecurityRate().SubResources([]string{"reset"}).Reset(ctx)
			if err != nil {
				fmt.Printf("Error: Failed to reset security rate statistics: %s\n", err.Error())
				return
			}
			defer resp.Body.Close()

			if resp.StatusCode == http.StatusOK || resp.StatusCode == http.StatusNoContent {
				fmt.Printf("Security rate statistics reset successfully\n")
				return
			} else {
				fmt.Printf("Failed to reset security rate statistics (HTTP %d)\n", resp.StatusCode)
			}
		},
	}
	return cmd
}
