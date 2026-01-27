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
package get

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"loxicmd/pkg/api"
	"net/http"
	"time"

	"github.com/spf13/cobra"
)

func NewGetLLMCatalogsCmd(restOptions *api.RESTOptions) *cobra.Command {
	var GetLLMCatalogsCmd = &cobra.Command{
		Use:     "llm-catalogs",
		Short:   "Get all LLM catalog profiles",
		Long:    `It shows all available LLM catalog profiles including built-in and custom catalogs`,
		Aliases: []string{"llmcatalogs", "llmcat"},

		Run: func(cmd *cobra.Command, args []string) {
			client := api.NewLoxiClient(restOptions)
			ctx := context.TODO()
			var cancel context.CancelFunc
			if restOptions.Timeout > 0 {
				ctx, cancel = context.WithTimeout(context.TODO(), time.Duration(restOptions.Timeout)*time.Second)
				defer cancel()
			}
			resp, err := client.LLMCatalog().GetAll(ctx)
			if err != nil {
				fmt.Printf("Error: %s\n", err.Error())
				return
			}
			if resp.StatusCode == http.StatusOK {
				PrintGetLLMCatalogsResult(resp, *restOptions)
				return
			}
		},
	}

	return GetLLMCatalogsCmd
}

func NewGetLLMCatalogCmd(restOptions *api.RESTOptions) *cobra.Command {
	var GetLLMCatalogCmd = &cobra.Command{
		Use:   "llm-catalog CATALOG_NAME",
		Short: "Get specific LLM catalog profile",
		Long:  `It shows details of a specific LLM catalog profile by name (e.g., chat-interactive, rag-longcontext, batch-inference, code-generation, default)`,

		Run: func(cmd *cobra.Command, args []string) {
			if len(args) == 0 {
				fmt.Println("Error: catalog name is required")
				return
			}
			catalogName := args[0]

			client := api.NewLoxiClient(restOptions)
			ctx := context.TODO()
			var cancel context.CancelFunc
			if restOptions.Timeout > 0 {
				ctx, cancel = context.WithTimeout(context.TODO(), time.Duration(restOptions.Timeout)*time.Second)
				defer cancel()
			}
			resp, err := client.LLMCatalog().Get(ctx, catalogName)
			if err != nil {
				fmt.Printf("Error: %s\n", err.Error())
				return
			}
			if resp.StatusCode == http.StatusOK {
				PrintGetLLMCatalogResult(resp, *restOptions)
				return
			} else if resp.StatusCode == http.StatusNotFound {
				fmt.Printf("Error: Catalog '%s' not found\n", catalogName)
				return
			}
		},
	}

	return GetLLMCatalogCmd
}

func PrintGetLLMCatalogsResult(resp *http.Response, o api.RESTOptions) {
	catalogs := []api.LLMCatalog{}
	resultByte, err := io.ReadAll(resp.Body)
	if err != nil {
		fmt.Printf("Error: Failed to read HTTP response: (%s)\n", err.Error())
		return
	}

	if err := json.Unmarshal(resultByte, &catalogs); err != nil {
		fmt.Printf("Error: Failed to unmarshal HTTP response: (%s)\n", err.Error())
		return
	}

	// If json option is enabled, print as JSON format
	if o.PrintOption == "json" {
		resultIndent, _ := json.MarshalIndent(catalogs, "", "    ")
		fmt.Println(string(resultIndent))
		return
	}

	// Table Init
	table := TableInit()
	table.SetHeader(LLM_CATALOG_TITLE)

	var data [][]string
	for _, catalog := range catalogs {
		builtinStr := "No"
		if catalog.IsBuiltin {
			builtinStr = "Yes"
		}
		data = append(data, []string{
			catalog.Name,
			catalog.Description,
			catalog.Version,
			builtinStr,
			fmt.Sprintf("%d%%", catalog.Weights.QueuedRequests),
			fmt.Sprintf("%d%%", catalog.Weights.SwappedRequests),
			fmt.Sprintf("%d%%", catalog.Weights.KVCacheUsagePerc),
		})
	}

	TableShow(data, table)
}

func PrintGetLLMCatalogResult(resp *http.Response, o api.RESTOptions) {
	catalog := api.LLMCatalog{}
	resultByte, err := io.ReadAll(resp.Body)
	if err != nil {
		fmt.Printf("Error: Failed to read HTTP response: (%s)\n", err.Error())
		return
	}

	if err := json.Unmarshal(resultByte, &catalog); err != nil {
		fmt.Printf("Error: Failed to unmarshal HTTP response: (%s)\n", err.Error())
		return
	}

	// If json option is enabled, print as JSON format
	if o.PrintOption == "json" {
		resultIndent, _ := json.MarshalIndent(catalog, "", "    ")
		fmt.Println(string(resultIndent))
		return
	}
	table := TableInit()

	var data [][]string
	if o.PrintOption == "wide" {
		table.SetHeader(LLM_CATALOG_DETAIL_TITLE)
		// In wide mode, print as JSON format for detailed view
		data = append(data, []string{
			catalog.Name,
			catalog.Description,
			catalog.Version,
			fmt.Sprintf("%d%%", catalog.Weights.QueuedRequests),
			fmt.Sprintf("%d%%", catalog.Weights.SwappedRequests),
			fmt.Sprintf("%d%%", catalog.Weights.KVCacheUsagePerc),
			fmt.Sprintf("%v", catalog.IsBuiltin),
			fmt.Sprintf("%d", catalog.Thresholds.QueueHigh),
			fmt.Sprintf("%d", catalog.Thresholds.QueueCritical),
			fmt.Sprintf("%d", catalog.Thresholds.SwapHigh),
			fmt.Sprintf("%d", catalog.Thresholds.SwapCritical),
			fmt.Sprintf("%d%%", catalog.Thresholds.CacheHigh),
			fmt.Sprintf("%d%%", catalog.Thresholds.CacheCritical),
		})
	} else {
		table.SetHeader(LLM_CATALOG_TITLE)
		// Print catalog details
		data = append(data, []string{
			catalog.Name,
			catalog.Description,
			catalog.Version,
			fmt.Sprintf("%v", catalog.IsBuiltin),
			fmt.Sprintf("%d%%", catalog.Weights.QueuedRequests),
			fmt.Sprintf("%d%%", catalog.Weights.SwappedRequests),
			fmt.Sprintf("%d%%", catalog.Weights.KVCacheUsagePerc),
		})
	}
	TableShow(data, table)
}
