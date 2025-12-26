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

package delete

import (
	"context"
	"encoding/json"
	"fmt"
	"loxicmd/pkg/api"
	"net/http"

	"github.com/spf13/cobra"
)

func NewDeleteL4TraceCmd(restOptions *api.RESTOptions) *cobra.Command {
	var DeleteL4TraceCmd = &cobra.Command{
		Use:   "l4trace",
		Short: "Disable L4 connection tracing",
		Long:  `Stop tracing TCP/SCTP connections`,
		Run: func(cmd *cobra.Command, args []string) {
			client := api.NewLoxiClient(restOptions)
			ctx := context.TODO()
			resp, err := client.L4Trace().Delete(ctx)
			if err != nil {
				fmt.Printf("Error: %s\n", err.Error())
				return
			}
			if resp.StatusCode == http.StatusOK {
				PrintL4TraceDeleteResult(resp, restOptions.PrintOption)
				return
			}
		},
	}

	return DeleteL4TraceCmd
}

func PrintL4TraceDeleteResult(resp *api.RESTResponse, printOption string) {
	if printOption == "json" {
		resultIndent, _ := json.MarshalIndent(resp, "", "\t")
		fmt.Println(string(resultIndent))
		return
	}
	fmt.Println("L4 tracing disabled successfully")
}
