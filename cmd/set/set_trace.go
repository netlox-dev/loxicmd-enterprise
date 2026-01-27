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
package set

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"loxicmd/pkg/api"
	"net/http"
	"strings"
	"time"

	"github.com/spf13/cobra"
)

func NewSetTraceCmd(restOptions *api.RESTOptions) *cobra.Command {
	var setTraceCmd = &cobra.Command{
		Use:   "trace",
		Short: "Manage HTTP/HTTPS protocol tracing",
		Long:  `Enable, disable, or configure HTTP/HTTPS protocol tracing and OTLP export.`,
	}

	setTraceCmd.AddCommand(NewSetTraceEnableCmd(restOptions))
	setTraceCmd.AddCommand(NewSetTraceDisableCmd(restOptions))
	setTraceCmd.AddCommand(NewSetTraceOTLPCmd(restOptions))
	setTraceCmd.AddCommand(NewSetTraceCatalogParserCmd(restOptions))

	return setTraceCmd
}

func NewSetTraceEnableCmd(restOptions *api.RESTOptions) *cobra.Command {
	var setTraceEnableCmd = &cobra.Command{
		Use:   "enable",
		Short: "Enable HTTP/HTTPS protocol tracing",
		Long: `Enable distributed tracing for all HTTP/HTTPS traffic passing through loxilb proxy.
Events are emitted to ring buffers for export to Jaeger/OpenTelemetry.

Examples:
  loxicmd set trace enable
`,
		Run: func(cmd *cobra.Command, args []string) {
			client := api.NewLoxiClient(restOptions)
			ctx := context.TODO()
			var cancel context.CancelFunc
			if restOptions.Timeout > 0 {
				ctx, cancel = context.WithTimeout(ctx, time.Duration(restOptions.Timeout)*time.Second)
				defer cancel()
			}

			resp, err := client.Trace().Post(ctx, "enable", nil)
			if err != nil {
				fmt.Printf("Error: Failed to enable tracing: %s\n", err.Error())
				return
			}
			defer resp.Body.Close()

			if resp.StatusCode == http.StatusOK {
				resultByte, _ := io.ReadAll(resp.Body)
				var result map[string]interface{}
				if err := json.Unmarshal(resultByte, &result); err == nil {
					if restOptions.PrintOption == "json" {
						resultIndent, _ := json.MarshalIndent(result, "", "  ")
						fmt.Println(string(resultIndent))
					} else {
						fmt.Println("HTTP/HTTPS tracing enabled successfully")
					}
				} else {
					fmt.Println("HTTP/HTTPS tracing enabled successfully")
				}
				return
			}

			resultByte, _ := io.ReadAll(resp.Body)
			fmt.Printf("Error: Failed to enable tracing: %s\n", string(resultByte))
		},
	}

	return setTraceEnableCmd
}

func NewSetTraceDisableCmd(restOptions *api.RESTOptions) *cobra.Command {
	var setTraceDisableCmd = &cobra.Command{
		Use:   "disable",
		Short: "Disable HTTP/HTTPS protocol tracing",
		Long: `Disable distributed tracing and stop emitting events to ring buffers.

Examples:
  loxicmd set trace disable
`,
		Run: func(cmd *cobra.Command, args []string) {
			client := api.NewLoxiClient(restOptions)
			ctx := context.TODO()
			var cancel context.CancelFunc
			if restOptions.Timeout > 0 {
				ctx, cancel = context.WithTimeout(ctx, time.Duration(restOptions.Timeout)*time.Second)
				defer cancel()
			}

			resp, err := client.Trace().Post(ctx, "disable", nil)
			if err != nil {
				fmt.Printf("Error: Failed to disable tracing: %s\n", err.Error())
				return
			}
			defer resp.Body.Close()

			if resp.StatusCode == http.StatusOK {
				resultByte, _ := io.ReadAll(resp.Body)
				var result map[string]interface{}
				if err := json.Unmarshal(resultByte, &result); err == nil {
					if restOptions.PrintOption == "json" {
						resultIndent, _ := json.MarshalIndent(result, "", "  ")
						fmt.Println(string(resultIndent))
					} else {
						fmt.Println("HTTP/HTTPS tracing disabled successfully")
					}
				} else {
					fmt.Println("HTTP/HTTPS tracing disabled successfully")
				}
				return
			}

			resultByte, _ := io.ReadAll(resp.Body)
			fmt.Printf("Error: Failed to disable tracing: %s\n", string(resultByte))
		},
	}

	return setTraceDisableCmd
}

func NewSetTraceOTLPCmd(restOptions *api.RESTOptions) *cobra.Command {
	var (
		endpoint      string
		protocol      string
		useTLS        bool
		tlsSkipVerify bool
		headers       []string
	)

	var setTraceOTLPCmd = &cobra.Command{
		Use:   "otlp",
		Short: "Configure OTLP endpoint for trace export",
		Long: `Sets the OpenTelemetry Protocol (OTLP) endpoint address and protocol for exporting distributed traces.

Security Features:
  - TLS encryption enabled by default (--use-tls)
  - TLS certificate verification (--tls-skip-verify=false)
  - Optional authentication headers (--header)
  - Endpoint validation (host:port format)

Production Recommendations:
  - Always use TLS (--use-tls=true) to encrypt trace data
  - Never skip TLS verification (--tls-skip-verify=false) in production
  - Use authentication headers for secured endpoints

Examples:
  # Configure gRPC endpoint with TLS
  loxicmd set trace otlp --endpoint=jaeger.example.com:4317 --protocol=grpc --use-tls=true

  # Configure HTTP endpoint with authentication
  loxicmd set trace otlp --endpoint=tempo.example.com:4318 --protocol=http --use-tls=true --header="Authorization=Bearer token123"

  # Configure with multiple headers
  loxicmd set trace otlp --endpoint=otel.example.com:4317 --protocol=grpc --header="X-API-Key=key123" --header="X-Tenant=prod"
`,
		Run: func(cmd *cobra.Command, args []string) {
			if endpoint == "" {
				fmt.Println("Error: --endpoint is required")
				return
			}
			if protocol == "" {
				fmt.Println("Error: --protocol is required (grpc or http)")
				return
			}
			if protocol != "grpc" && protocol != "http" {
				fmt.Println("Error: --protocol must be 'grpc' or 'http'")
				return
			}

			client := api.NewLoxiClient(restOptions)
			ctx := context.TODO()
			var cancel context.CancelFunc
			if restOptions.Timeout > 0 {
				ctx, cancel = context.WithTimeout(ctx, time.Duration(restOptions.Timeout)*time.Second)
				defer cancel()
			}

			// Parse headers
			headerMap := make(map[string]string)
			for _, h := range headers {
				parts := strings.SplitN(h, "=", 2)
				if len(parts) == 2 {
					headerMap[parts[0]] = parts[1]
				} else {
					fmt.Printf("Warning: Invalid header format '%s', skipping\n", h)
				}
			}

			otlpConfig := api.OTLPConfigRequest{
				Endpoint:      endpoint,
				Protocol:      protocol,
				UseTLS:        useTLS,
				TLSSkipVerify: tlsSkipVerify,
				Headers:       headerMap,
			}

			resp, err := client.Trace().Post(ctx, "otlp", otlpConfig)
			if err != nil {
				fmt.Printf("Error: Failed to configure OTLP endpoint: %s\n", err.Error())
				return
			}
			defer resp.Body.Close()

			if resp.StatusCode == http.StatusOK {
				resultByte, _ := io.ReadAll(resp.Body)
				var result map[string]interface{}
				if err := json.Unmarshal(resultByte, &result); err == nil {
					if restOptions.PrintOption == "json" {
						resultIndent, _ := json.MarshalIndent(result, "", "  ")
						fmt.Println(string(resultIndent))
					} else {
						fmt.Printf("OTLP endpoint configured successfully: %s (%s)\n", endpoint, protocol)
					}
				} else {
					fmt.Printf("OTLP endpoint configured successfully: %s (%s)\n", endpoint, protocol)
				}
				return
			}

			resultByte, _ := io.ReadAll(resp.Body)
			fmt.Printf("Error: Failed to configure OTLP endpoint: %s\n", string(resultByte))
		},
	}

	setTraceOTLPCmd.Flags().StringVarP(&endpoint, "endpoint", "e", "", "OTLP endpoint address (host:port)")
	setTraceOTLPCmd.Flags().StringVar(&protocol, "protocol", "grpc", "OTLP protocol (grpc or http)")
	setTraceOTLPCmd.Flags().BoolVar(&useTLS, "use-tls", true, "Enable TLS encryption (default: true)")
	setTraceOTLPCmd.Flags().BoolVar(&tlsSkipVerify, "tls-skip-verify", false, "Skip TLS certificate verification (INSECURE, default: false)")
	setTraceOTLPCmd.Flags().StringSliceVarP(&headers, "header", "H", nil, "Authentication headers (format: key=value)")

	setTraceOTLPCmd.MarkFlagRequired("endpoint")
	setTraceOTLPCmd.MarkFlagRequired("protocol")

	return setTraceOTLPCmd
}

func NewSetTraceCatalogParserCmd(restOptions *api.RESTOptions) *cobra.Command {
	var (
		catalogID  int
		parserName string
	)

	var setTraceCatalogParserCmd = &cobra.Command{
		Use:   "catalog-parser",
		Short: "Update parser assignment for a catalog",
		Long: `Dynamically changes which parser is used for a specific catalog at runtime.
This allows switching parsers without restarting loxilb or reloading YAML files.

Use Cases:
  - Switch from mock to production parser after testing
  - Change parser when service protocol changes
  - A/B testing different parser implementations

Parser Selection Priority:
  1. Catalog ID → parser mapping (set by this command or YAML)
  2. URL path prefix matching (e.g., /v1/chat/completions → openai)
  3. Default mock parser

Examples:
  # Assign openai parser to catalog ID 1
  loxicmd set trace catalog-parser --catalog-id=1 --parser=openai

  # Switch to mcp parser for catalog ID 5
  loxicmd set trace catalog-parser --catalog-id=5 --parser=mcp

  # Assign mock parser for testing
  loxicmd set trace catalog-parser --catalog-id=2 --parser=mock
`,
		Run: func(cmd *cobra.Command, args []string) {
			if catalogID < 1 || catalogID > 255 {
				fmt.Println("Error: --catalog-id must be between 1 and 255")
				return
			}
			if parserName == "" {
				fmt.Println("Error: --parser is required")
				return
			}

			client := api.NewLoxiClient(restOptions)
			ctx := context.TODO()
			var cancel context.CancelFunc
			if restOptions.Timeout > 0 {
				ctx, cancel = context.WithTimeout(ctx, time.Duration(restOptions.Timeout)*time.Second)
				defer cancel()
			}

			parserUpdate := api.TraceParserUpdate{
				ParserName: parserName,
			}

			resp, err := client.Trace().Put(ctx, catalogID, parserUpdate)
			if err != nil {
				fmt.Printf("Error: Failed to update catalog parser: %s\n", err.Error())
				return
			}
			defer resp.Body.Close()

			if resp.StatusCode == http.StatusOK {
				fmt.Printf("Catalog parser updated successfully (catalog ID: %d, parser: %s)\n", catalogID, parserName)
				return
			}

			resultByte, _ := io.ReadAll(resp.Body)
			fmt.Printf("Error: Failed to update catalog parser: %s\n", string(resultByte))
		},
	}

	setTraceCatalogParserCmd.Flags().IntVar(&catalogID, "catalog-id", 0, "Catalog ID (1-255)")
	setTraceCatalogParserCmd.Flags().StringVarP(&parserName, "parser", "", "", "Parser name (e.g., openai, mcp, mock)")

	setTraceCatalogParserCmd.MarkFlagRequired("catalog-id")
	setTraceCatalogParserCmd.MarkFlagRequired("parser")

	return setTraceCatalogParserCmd
}
