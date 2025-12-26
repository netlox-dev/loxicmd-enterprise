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
	"time"

	"loxicmd/pkg/api"

	"github.com/spf13/cobra"
)

func NewDeleteSYNFloodCmd(restOptions *api.RESTOptions) *cobra.Command {
	var deleteSYNFloodCmd = &cobra.Command{
		Use:   "synflood",
		Short: "Disable SYN flood protection",
		Long: `Disable SYN flood protection in LoxiLB

This command disables SYN flood protection by setting the enabled flag to false.
The configuration (thresholds and whitelist) is preserved but protection is deactivated.

Effects:
  - SYN flood rate limiting is disabled
  - SYN cookies are deactivated
  - All SYN packets are processed normally
  - Statistics are reset to zero
  - Whitelist configuration is cleared

To re-enable protection, use: loxicmd create synflood

Examples:
  # Disable SYN flood protection
  loxicmd delete synflood

  # Verify disabled state
  loxicmd get synflood

Use Cases:
  - Temporary disable during maintenance
  - Testing without rate limiting
  - Remove protection after attack subsides
  - Reconfigure with different thresholds
`,
		Aliases: []string{"SYNFlood", "synf", "syn-flood"},
		Run: func(cmd *cobra.Command, args []string) {
			client := api.NewLoxiClient(restOptions)
			ctx := context.TODO()
			var cancel context.CancelFunc
			if restOptions.Timeout > 0 {
				ctx, cancel = context.WithTimeout(ctx, time.Duration(restOptions.Timeout)*time.Second)
				defer cancel()
			}

			resp, err := client.SYNFlood().Delete(ctx)
			if err != nil {
				fmt.Printf("Error: Failed to disable SYN flood protection: %s\n", err.Error())
				return
			}
			defer resp.Body.Close()

			fmt.Printf("Debug: response.StatusCode: %d\n", resp.StatusCode)
			if resp.StatusCode == http.StatusOK || resp.StatusCode == http.StatusNoContent {
				fmt.Printf("✅ SYN flood protection disabled successfully\n")
				return
			} else {
				PrintDeleteResult(resp, *restOptions)
			}
		},
	}

	return deleteSYNFloodCmd
}
