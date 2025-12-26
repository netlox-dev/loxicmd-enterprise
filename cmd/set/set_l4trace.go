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

package set

import (
	"context"
	"encoding/json"
	"fmt"
	"loxicmd/pkg/api"
	"net/http"

	"github.com/spf13/cobra"
)

type L4TraceSamplingMod struct {
	SamplingRate int64 `json:"sampling_rate"`
}

func NewSetL4TraceSamplingCmd(restOptions *api.RESTOptions) *cobra.Command {
	var l4TraceSamplingMod L4TraceSamplingMod

	var SetL4TraceSamplingCmd = &cobra.Command{
		Use:   "l4trace-sampling",
		Short: "Update L4 tracing sampling rate",
		Long: `Set the percentage of connections to trace (0-100).
Examples:
  # Set to 50% sampling
  loxicmd set l4trace-sampling --rate 50

  # Set to 10% sampling (light overhead)
  loxicmd set l4trace-sampling --rate 10`,
		Run: func(cmd *cobra.Command, args []string) {
			// Validate sampling rate
			if l4TraceSamplingMod.SamplingRate < 0 || l4TraceSamplingMod.SamplingRate > 100 {
				fmt.Println("Error: Sampling rate must be between 0 and 100")
				return
			}

			client := api.NewLoxiClient(restOptions)
			ctx := context.TODO()
			resp, err := client.L4Trace().SetSampling(ctx, &l4TraceSamplingMod)
			if err != nil {
				fmt.Printf("Error: %s\n", err.Error())
				return
			}
			if resp.StatusCode == http.StatusOK {
				PrintSetResult(resp, restOptions.PrintOption)
				return
			}
		},
	}

	SetL4TraceSamplingCmd.Flags().Int64VarP(&l4TraceSamplingMod.SamplingRate, "rate", "r", 100,
		"Sampling rate (0-100 percent)")
	SetL4TraceSamplingCmd.MarkFlagRequired("rate")

	return SetL4TraceSamplingCmd
}

func PrintSetResult(resp *api.RESTResponse, printOption string) {
	if printOption == "json" {
		resultIndent, _ := json.MarshalIndent(resp, "", "\t")
		fmt.Println(string(resultIndent))
		return
	}
	fmt.Println("L4 trace sampling rate updated successfully")
}
