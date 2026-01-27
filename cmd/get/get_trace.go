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
package get

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"loxicmd/pkg/api"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/cobra"
)

func NewGetTraceCmd(restOptions *api.RESTOptions) *cobra.Command {
	var getTraceCmd = &cobra.Command{
		Use:   "trace",
		Short: "Get HTTP/HTTPS tracing information",
		Long:  `Get tracing status, OTLP configuration, catalogs, parsers, and catalog-parser mappings.`,
	}

	getTraceCmd.AddCommand(NewGetTraceStatusCmd(restOptions))
	getTraceCmd.AddCommand(NewGetTraceOTLPCmd(restOptions))
	getTraceCmd.AddCommand(NewGetTraceCatalogsCmd(restOptions))
	getTraceCmd.AddCommand(NewGetTraceParsersCmd(restOptions))
	getTraceCmd.AddCommand(NewGetTraceCatalogParserCmd(restOptions))

	return getTraceCmd
}

func NewGetTraceStatusCmd(restOptions *api.RESTOptions) *cobra.Command {
	var getTraceStatusCmd = &cobra.Command{
		Use:   "status",
		Short: "Get HTTP/HTTPS tracing status",
		Long: `Returns current tracing status, ring buffer statistics, and OTLP endpoint configuration.

Examples:
  loxicmd get trace status
  loxicmd get trace status -o json
`,
		Run: func(cmd *cobra.Command, args []string) {
			client := api.NewLoxiClient(restOptions)
			ctx := context.TODO()
			var cancel context.CancelFunc
			if restOptions.Timeout > 0 {
				ctx, cancel = context.WithTimeout(ctx, time.Duration(restOptions.Timeout)*time.Second)
				defer cancel()
			}

			resp, err := client.Trace().Get(ctx, "status", "")
			if err != nil {
				fmt.Printf("Error: Failed to get trace status: %s\n", err.Error())
				return
			}
			defer resp.Body.Close()

			if resp.StatusCode == http.StatusOK {
				PrintTraceStatus(resp, *restOptions)
				return
			}

			resultByte, _ := io.ReadAll(resp.Body)
			fmt.Printf("Error: Failed to get trace status: %s\n", string(resultByte))
		},
	}

	return getTraceStatusCmd
}

func NewGetTraceOTLPCmd(restOptions *api.RESTOptions) *cobra.Command {
	var getTraceOTLPCmd = &cobra.Command{
		Use:   "otlp",
		Short: "Get OTLP endpoint configuration",
		Long: `Returns current OTLP endpoint address, protocol, TLS settings, and connection status.

Examples:
  loxicmd get trace otlp
  loxicmd get trace otlp -o json
`,
		Run: func(cmd *cobra.Command, args []string) {
			client := api.NewLoxiClient(restOptions)
			ctx := context.TODO()
			var cancel context.CancelFunc
			if restOptions.Timeout > 0 {
				ctx, cancel = context.WithTimeout(ctx, time.Duration(restOptions.Timeout)*time.Second)
				defer cancel()
			}

			resp, err := client.Trace().Get(ctx, "otlp", "")
			if err != nil {
				fmt.Printf("Error: Failed to get OTLP configuration: %s\n", err.Error())
				return
			}
			defer resp.Body.Close()

			if resp.StatusCode == http.StatusOK {
				PrintTraceOTLP(resp, *restOptions)
				return
			}

			resultByte, _ := io.ReadAll(resp.Body)
			fmt.Printf("Error: Failed to get OTLP configuration: %s\n", string(resultByte))
		},
	}

	return getTraceOTLPCmd
}

func NewGetTraceCatalogsCmd(restOptions *api.RESTOptions) *cobra.Command {
	var getTraceCatalogsCmd = &cobra.Command{
		Use:   "catalogs",
		Short: "List all loaded trace catalogs",
		Long: `Returns a list of all tracing catalog templates loaded from YAML files.
Catalogs define parser assignments, sampling rates, and tracing behavior for different services.

Examples:
  loxicmd get trace catalogs
  loxicmd get trace catalogs -o json
`,
		Run: func(cmd *cobra.Command, args []string) {
			client := api.NewLoxiClient(restOptions)
			ctx := context.TODO()
			var cancel context.CancelFunc
			if restOptions.Timeout > 0 {
				ctx, cancel = context.WithTimeout(ctx, time.Duration(restOptions.Timeout)*time.Second)
				defer cancel()
			}

			resp, err := client.Trace().Get(ctx, "catalogs", "")
			if err != nil {
				fmt.Printf("Error: Failed to get trace catalogs: %s\n", err.Error())
				return
			}
			defer resp.Body.Close()

			if resp.StatusCode == http.StatusOK {
				PrintTraceCatalogs(resp, *restOptions)
				return
			}

			resultByte, _ := io.ReadAll(resp.Body)
			fmt.Printf("Error: Failed to get trace catalogs: %s\n", string(resultByte))
		},
	}

	return getTraceCatalogsCmd
}

func NewGetTraceParsersCmd(restOptions *api.RESTOptions) *cobra.Command {
	var getTraceParsersCmd = &cobra.Command{
		Use:   "parsers",
		Short: "List all available trace parsers",
		Long: `Returns a list of all protocol parsers registered in the tracing system.
Parsers analyze HTTP/HTTPS request/response bodies to extract protocol-specific attributes.

Examples:
  loxicmd get trace parsers
  loxicmd get trace parsers -o json
`,
		Run: func(cmd *cobra.Command, args []string) {
			client := api.NewLoxiClient(restOptions)
			ctx := context.TODO()
			var cancel context.CancelFunc
			if restOptions.Timeout > 0 {
				ctx, cancel = context.WithTimeout(ctx, time.Duration(restOptions.Timeout)*time.Second)
				defer cancel()
			}

			resp, err := client.Trace().Get(ctx, "parsers", "")
			if err != nil {
				fmt.Printf("Error: Failed to get trace parsers: %s\n", err.Error())
				return
			}
			defer resp.Body.Close()

			if resp.StatusCode == http.StatusOK {
				PrintTraceParsers(resp, *restOptions)
				return
			}

			resultByte, _ := io.ReadAll(resp.Body)
			fmt.Printf("Error: Failed to get trace parsers: %s\n", string(resultByte))
		},
	}

	return getTraceParsersCmd
}

func NewGetTraceCatalogParserCmd(restOptions *api.RESTOptions) *cobra.Command {
	var catalogID int

	var getCatalogParserCmd = &cobra.Command{
		Use:   "catalog-parser",
		Short: "Get parser assignment for a catalog",
		Long: `Returns the parser currently assigned to a specific trace catalog.

Examples:
  loxicmd get trace catalog-parser --catalog-id=1
  loxicmd get trace catalog-parser --catalog-id=5 -o json
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

			resp, err := client.Trace().Get(ctx, "catalog", strconv.Itoa(catalogID)+"/parser")
			if err != nil {
				fmt.Printf("Error: Failed to get catalog parser mapping: %s\n", err.Error())
				return
			}
			defer resp.Body.Close()

			if resp.StatusCode == http.StatusOK {
				PrintCatalogParser(resp, *restOptions)
				return
			}

			resultByte, _ := io.ReadAll(resp.Body)
			fmt.Printf("Error: Failed to get catalog parser mapping: %s\n", string(resultByte))
		},
	}

	getCatalogParserCmd.Flags().IntVar(&catalogID, "catalog-id", 0, "Catalog ID (1-255)")
	getCatalogParserCmd.MarkFlagRequired("catalog-id")

	return getCatalogParserCmd
}

// Print functions

func PrintTraceStatus(resp *http.Response, o api.RESTOptions) {
	var status api.TraceStatusResponse

	resultByte, err := io.ReadAll(resp.Body)
	if err != nil {
		fmt.Printf("Error: Failed to read HTTP response: %s\n", err.Error())
		return
	}

	if err := json.Unmarshal(resultByte, &status); err != nil {
		fmt.Printf("Error: Failed to unmarshal HTTP response: %s\n", err.Error())
		return
	}

	if o.PrintOption == "json" {
		resultIndent, _ := json.MarshalIndent(status, "", "  ")
		fmt.Println(string(resultIndent))
		return
	}

	// Table output
	table := TableInit()
	table.SetHeader([]string{"PROPERTY", "VALUE"})

	ringUtil := fmt.Sprintf("%v", status.RingUtilization)

	var data [][]string
	data = append(data, []string{"Enabled", fmt.Sprintf("%v", status.Enabled)})
	data = append(data, []string{"Total Events", fmt.Sprintf("%d", status.TotalEvents)})
	data = append(data, []string{"Dropped Events", fmt.Sprintf("%d", status.DroppedEvents)})
	data = append(data, []string{"OTLP Endpoint", status.OTLPEndpoint})
	data = append(data, []string{"OTLP Protocol", status.OTLPProtocol})
	data = append(data, []string{"OTLP Connected", fmt.Sprintf("%v", status.OTLPConnected)})
	if len(status.RingUtilization) > 0 {
		data = append(data, []string{"Ring Utilization", ringUtil})
	}

	TableShow(data, table)
}

func PrintTraceOTLP(resp *http.Response, o api.RESTOptions) {
	var otlpConfig api.OTLPConfigResponse

	resultByte, err := io.ReadAll(resp.Body)
	if err != nil {
		fmt.Printf("Error: Failed to read HTTP response: %s\n", err.Error())
		return
	}

	if err := json.Unmarshal(resultByte, &otlpConfig); err != nil {
		fmt.Printf("Error: Failed to unmarshal HTTP response: %s\n", err.Error())
		return
	}

	if o.PrintOption == "json" {
		resultIndent, _ := json.MarshalIndent(otlpConfig, "", "  ")
		fmt.Println(string(resultIndent))
		return
	}

	// Table output
	table := TableInit()
	table.SetHeader(TRACE_TITLE)

	var data [][]string
	var firstRow []string

	firstRow = []string{
		otlpConfig.Endpoint,
		otlpConfig.Protocol,
		fmt.Sprintf("%v", otlpConfig.UseTLS),
		fmt.Sprintf("%v", otlpConfig.TLSSkipVerify),
		fmt.Sprintf("%v", otlpConfig.Connected),
	}

	// Handle headers
	if len(otlpConfig.Headers) > 0 {
		headerCount := 0
		for k, v := range otlpConfig.Headers {
			if headerCount == 0 {
				// First header goes on the same row as the endpoint info
				firstRow = append(firstRow, k, v)
				data = append(data, firstRow)
			} else {
				// Remaining headers go on separate rows
				data = append(data, []string{"", "", "", "", "", k, v})
			}
			headerCount++
		}
	} else {
		data = append(data, firstRow)
	}

	TableShow(data, table)
}

func PrintTraceCatalogs(resp *http.Response, o api.RESTOptions) {
	var catalogsResp api.TraceCatalogsResponse

	resultByte, err := io.ReadAll(resp.Body)
	if err != nil {
		fmt.Printf("Error: Failed to read HTTP response: %s\n", err.Error())
		return
	}

	if err := json.Unmarshal(resultByte, &catalogsResp); err != nil {
		fmt.Printf("Error: Failed to unmarshal HTTP response: %s\n", err.Error())
		return
	}

	if o.PrintOption == "json" {
		resultIndent, _ := json.MarshalIndent(catalogsResp, "", "  ")
		fmt.Println(string(resultIndent))
		return
	}

	// Table output
	if len(catalogsResp.Catalogs) == 0 {
		fmt.Println("No trace catalogs loaded")
		return
	}

	table := TableInit()
	table.SetHeader([]string{"ID", "NAME", "VERSION", "SAMPLE_RATE", "PARSER", "ENABLED"})

	var data [][]string
	for _, catalog := range catalogsResp.Catalogs {
		enabled := "Yes"
		if !catalog.Enabled {
			enabled = "No"
		}
		data = append(data, []string{
			fmt.Sprintf("%d", catalog.CatalogID),
			catalog.CatalogName,
			catalog.Version,
			fmt.Sprintf("%d", catalog.SampleRate),
			catalog.ParserType,
			enabled,
		})
	}

	TableShow(data, table)
}

func PrintTraceParsers(resp *http.Response, o api.RESTOptions) {
	var parsersResp api.TraceParsersResponse

	resultByte, err := io.ReadAll(resp.Body)
	if err != nil {
		fmt.Printf("Error: Failed to read HTTP response: %s\n", err.Error())
		return
	}

	if err := json.Unmarshal(resultByte, &parsersResp); err != nil {
		fmt.Printf("Error: Failed to unmarshal HTTP response: %s\n", err.Error())
		return
	}

	if o.PrintOption == "json" {
		resultIndent, _ := json.MarshalIndent(parsersResp, "", "  ")
		fmt.Println(string(resultIndent))
		return
	}

	// Table output
	if len(parsersResp.Parsers) == 0 {
		fmt.Println("No trace parsers available")
		return
	}

	table := TableInit()
	table.SetHeader([]string{"NAME", "PROTOCOL", "VERSION", "PATHS"})

	var data [][]string
	for _, parser := range parsersResp.Parsers {
		paths := strings.Join(parser.SupportedPaths, ", ")
		if len(paths) > 50 {
			paths = paths[:47] + "..."
		}
		data = append(data, []string{
			parser.Name,
			parser.Protocol,
			parser.Version,
			paths,
		})
	}

	TableShow(data, table)
}

func PrintCatalogParser(resp *http.Response, o api.RESTOptions) {
	var mapping api.CatalogParserMapping

	resultByte, err := io.ReadAll(resp.Body)
	if err != nil {
		fmt.Printf("Error: Failed to read HTTP response: %s\n", err.Error())
		return
	}

	if err := json.Unmarshal(resultByte, &mapping); err != nil {
		fmt.Printf("Error: Failed to unmarshal HTTP response: %s\n", err.Error())
		return
	}

	if o.PrintOption == "json" {
		resultIndent, _ := json.MarshalIndent(mapping, "", "  ")
		fmt.Println(string(resultIndent))
		return
	}

	// Table output
	table := TableInit()
	table.SetHeader([]string{"PROPERTY", "VALUE"})

	var data [][]string
	data = append(data, []string{"Catalog ID", fmt.Sprintf("%d", mapping.CatalogID)})
	data = append(data, []string{"Catalog Name", mapping.CatalogName})
	data = append(data, []string{"Parser Name", mapping.ParserName})
	data = append(data, []string{"Parser Type", mapping.ParserType})

	TableShow(data, table)
}
