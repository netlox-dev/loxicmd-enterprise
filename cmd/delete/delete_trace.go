/*
 * Copyright (c) 2024 NetLOX Inc
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
	"io"
	"loxicmd/pkg/api"
	"net/http"
	"strconv"
	"time"

	"github.com/spf13/cobra"
)

func NewDeleteTraceCmd(restOptions *api.RESTOptions) *cobra.Command {
	var deleteTraceCmd = &cobra.Command{
		Use:   "trace",
		Short: "Delete trace-related configurations",
		Long:  `Remove catalog parser mappings or other trace configurations.`,
	}

	deleteTraceCmd.AddCommand(NewDeleteTraceCatalogParserCmd(restOptions))

	return deleteTraceCmd
}

func NewDeleteTraceCatalogParserCmd(restOptions *api.RESTOptions) *cobra.Command {
	var catalogID int

	var deleteCatalogParserCmd = &cobra.Command{
		Use:   "catalog-parser",
		Short: "Remove parser assignment for a catalog",
		Long: `Removes the catalog → parser mapping, causing the system to fall back to:
  1. URL path-based routing (e.g., /v1/chat/completions → openai)
  2. Default mock parser

Use this to revert to path-based parser selection or remove custom assignments.

Examples:
  loxicmd delete trace catalog-parser --catalog-id=1
  loxicmd delete trace catalog-parser --catalog-id=5
`,
		Run: func(cmd *cobra.Command, args []string) {
			if catalogID < 1 || catalogID > 255 {
				fmt.Println("Error: --catalog-id must be between 1 and 255")
				return
			}

			client := api.NewLoxiClient(restOptions)
			ctx := context.TODO()
			var cancel context.CancelFunc
			if restOptions.Timeout > 0 {
				ctx, cancel = context.WithTimeout(ctx, time.Duration(restOptions.Timeout)*time.Second)
				defer cancel()
			}

			resp, err := client.Trace().Delete(ctx, "catalog/"+strconv.Itoa(catalogID)+"/parser", "")
			if err != nil {
				fmt.Printf("Error: Failed to delete catalog parser mapping: %s\n", err.Error())
				return
			}
			defer resp.Body.Close()

			if resp.StatusCode == http.StatusOK || resp.StatusCode == http.StatusNoContent {
				fmt.Printf("Catalog parser mapping removed successfully (catalog ID: %d)\n", catalogID)
				return
			}

			resultByte, _ := io.ReadAll(resp.Body)
			fmt.Printf("Error: Failed to delete catalog parser mapping: %s\n", string(resultByte))
		},
	}

	deleteCatalogParserCmd.Flags().IntVar(&catalogID, "catalog-id", 0, "Catalog ID (1-255)")
	deleteCatalogParserCmd.MarkFlagRequired("catalog-id")

	return deleteCatalogParserCmd
}
