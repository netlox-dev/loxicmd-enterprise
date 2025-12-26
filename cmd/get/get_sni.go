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
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/spf13/cobra"
)

func NewGetSNICertificateCmd(restOptions *api.RESTOptions) *cobra.Command {
	var getSNICmd = &cobra.Command{
		Use:     "sni",
		Short:   "Get all global SNI certificates",
		Aliases: []string{"snicert", "snicertificates"},
		Long: `List all global SNI certificate mappings.

Examples:
  loxicmd get sni
`,
		Run: func(cmd *cobra.Command, args []string) {
			client := api.NewLoxiClient(restOptions)
			ctx := context.TODO()
			var cancel context.CancelFunc
			if restOptions.Timeout > 0 {
				ctx, cancel = context.WithTimeout(ctx, time.Duration(restOptions.Timeout)*time.Second)
				defer cancel()
			}

			resp, err := client.SNICertificate().Get(ctx)
			if err != nil {
				fmt.Printf("Error: Failed to get SNI certificates: %s\n", err.Error())
				return
			}
			defer resp.Body.Close()

			if resp.StatusCode == http.StatusOK {
				PrintGetSNIResult(resp, *restOptions)
				return
			}

			// Handle non-OK responses
			resultByte, _ := io.ReadAll(resp.Body)
			fmt.Printf("Error: Failed to get SNI certificates: %s\n", string(resultByte))
		},
	}

	return getSNICmd
}

func PrintGetSNIResult(resp *http.Response, o api.RESTOptions) {
	sniResp := api.SNICertificateGetResponse{}
	var data [][]string

	resultByte, err := io.ReadAll(resp.Body)
	if err != nil {
		fmt.Printf("Error: Failed to read HTTP response: (%s)\n", err.Error())
		return
	}

	if err := json.Unmarshal(resultByte, &sniResp); err != nil {
		fmt.Printf("Error: Failed to unmarshal HTTP response: (%s)\n", err.Error())
		return
	}

	if o.PrintOption == "json" {
		resultIndent, _ := json.MarshalIndent(sniResp, "", "  ")
		fmt.Println(string(resultIndent))
		return
	}

	// Table output format
	if len(sniResp.SniAttr) == 0 {
		fmt.Println("No SNI certificates registered")
		return
	}

	// Print table header
	data = append(data, []string{"HOSTNAME", "CERT-PATH"})

	// Print each certificate entry
	for _, attr := range sniResp.SniAttr {
		hostname := "N/A"
		if attr.Hostname != nil {
			hostname = *attr.Hostname
		}

		certPath := "default"
		if attr.CertPath != "" {
			certPath = attr.CertPath
		}

		data = append(data, []string{hostname, certPath})
	}

	// Print table
	PrintTable(data)
}

func PrintTable(data [][]string) {
	if len(data) == 0 {
		return
	}

	// Calculate column widths
	colWidths := make([]int, len(data[0]))
	for _, row := range data {
		for i, cell := range row {
			if len(cell) > colWidths[i] {
				colWidths[i] = len(cell)
			}
		}
	}

	// Check if we can use 'column' command for better formatting
	if _, err := exec.LookPath("column"); err == nil {
		// Use column command
		var output strings.Builder
		for _, row := range data {
			output.WriteString(strings.Join(row, "\t"))
			output.WriteString("\n")
		}
		cmd := exec.Command("column", "-t", "-s", "\t")
		cmd.Stdin = strings.NewReader(output.String())
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		_ = cmd.Run()
	} else {
		// Manual table formatting
		for i, row := range data {
			for j, cell := range row {
				fmt.Printf("%-*s  ", colWidths[j], cell)
			}
			fmt.Println()
			if i == 0 {
				// Print separator after header
				for j := range row {
					fmt.Print(strings.Repeat("-", colWidths[j]))
					fmt.Print("  ")
				}
				fmt.Println()
			}
		}
	}
}
