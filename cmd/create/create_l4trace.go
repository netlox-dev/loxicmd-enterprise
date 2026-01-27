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

package create

import (
	"context"
	"encoding/json"
	"fmt"
	"loxicmd/pkg/api"
	"net/http"

	"github.com/spf13/cobra"
)

type L4TraceEnableMod struct {
	SamplingRate int64 `json:"sampling_rate"`
}

func NewCreateL4TraceCmd(restOptions *api.RESTOptions) *cobra.Command {
	var l4TraceEnableMod L4TraceEnableMod

	var CreateL4TraceCmd = &cobra.Command{
		Use:   "l4trace",
		Short: "Enable L4 connection tracing",
		Long: `Enable distributed tracing for TCP/SCTP connections.
Examples:
  # Enable with 100% sampling (trace all connections)
  loxicmd create l4trace --sampling 100

  # Enable with 10% sampling (production mode)
  loxicmd create l4trace --sampling 10`,
		Run: func(cmd *cobra.Command, args []string) {
			// Validate sampling rate
			if l4TraceEnableMod.SamplingRate < 0 || l4TraceEnableMod.SamplingRate > 100 {
				fmt.Println("Error: Sampling rate must be between 0 and 100")
				return
			}

			client := api.NewLoxiClient(restOptions)
			ctx := context.TODO()
			resp, err := client.L4Trace().Create(ctx, &l4TraceEnableMod)
			if err != nil {
				fmt.Printf("Error: %s\n", err.Error())
				return
			}
			if resp.StatusCode == http.StatusOK {
				PrintL4TraceCreateResult(resp, restOptions.PrintOption)
				return
			}
		},
	}

	CreateL4TraceCmd.Flags().Int64VarP(&l4TraceEnableMod.SamplingRate, "sampling", "", 100, "Sampling rate (0-100 percent, default: 100)")

	return CreateL4TraceCmd
}

func PrintL4TraceCreateResult(resp *api.RESTResponse, printOption string) {
	if printOption == "json" {
		resultIndent, _ := json.MarshalIndent(resp, "", "\t")
		fmt.Println(string(resultIndent))
		return
	}
	fmt.Println("L4 tracing enabled successfully")
}
