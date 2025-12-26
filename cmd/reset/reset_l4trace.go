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

package reset

import (
	"fmt"
	"loxicmd/pkg/api"
	"net/http"

	"github.com/spf13/cobra"
)

func NewResetL4TraceStatsCmd(restOptions *api.RESTOptions) *cobra.Command {
	var ResetL4TraceStatsCmd = &cobra.Command{
		Use:   "l4trace-stats",
		Short: "Reset L4 tracing statistics",
		Long:  `Clear all L4 connection tracing statistics counters`,
		Run: func(cmd *cobra.Command, args []string) {
			client := api.NewLoxiClient(restOptions)
			ctx := api.NewCLIContext()
			resp, err := client.L4Trace().ResetStats(ctx)
			if err != nil {
				fmt.Printf("Error: %s\n", err.Error())
				return
			}
			if resp.StatusCode == http.StatusOK {
				PrintResetResult(resp, restOptions.PrintOption)
				return
			}
		},
	}

	return ResetL4TraceStatsCmd
}
