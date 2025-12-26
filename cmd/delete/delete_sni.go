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
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"loxicmd/pkg/api"
	"net/http"
	"time"

	"github.com/spf13/cobra"
)

type DeleteSNICertificateResult struct {
	Result string `json:"result"`
}

func validateSNIArgs(args []string) error {
	if len(args) > 1 {
		return errors.New("delete sni command has too many args")
	} else if len(args) < 1 {
		return errors.New("delete sni needs HOSTNAME arg")
	}
	return nil
}

func NewDeleteSNICertificateCmd(restOptions *api.RESTOptions) *cobra.Command {
	var deleteSNICmd = &cobra.Command{
		Use:   "sni HOSTNAME",
		Short: "Unregister SNI certificate globally",
		Long: `Unregister an SNI certificate from the global store.

This removes the certificate association but does not delete the certificate files from the filesystem.

Examples:
  loxicmd delete sni api.example.com
  loxicmd delete sni web.example.com
`,
		PreRun: func(cmd *cobra.Command, args []string) {
			// Validation handled in Run
		},
		Run: func(cmd *cobra.Command, args []string) {
			if err := validateSNIArgs(args); err != nil {
				fmt.Println(err)
				return
			}

			hostname := args[0]
			if hostname == "" {
				fmt.Println("Error: hostname cannot be empty")
				return
			}

			client := api.NewLoxiClient(restOptions)
			ctx := context.TODO()
			var cancel context.CancelFunc
			if restOptions.Timeout > 0 {
				ctx, cancel = context.WithTimeout(ctx, time.Duration(restOptions.Timeout)*time.Second)
				defer cancel()
			}

			sniModel := api.SNICertificateEntry{
				Hostname: &hostname,
			}

			resp, err := client.SNICertificate().Delete(ctx, sniModel)
			if err != nil {
				fmt.Printf("Error: Failed to unregister SNI certificate (Hostname: %s): %s\n",
					hostname, err.Error())
				return
			}
			defer resp.Body.Close()

			fmt.Printf("Debug: response.StatusCode: %d\n", resp.StatusCode)
			if resp.StatusCode == http.StatusOK {
				PrintDeleteSNIResult(resp, *restOptions)
				return
			}

			// Handle non-OK responses
			resultByte, _ := io.ReadAll(resp.Body)
			fmt.Printf("Error: Failed to unregister SNI certificate: %s\n", string(resultByte))
		},
	}

	return deleteSNICmd
}

func PrintDeleteSNIResult(resp *http.Response, o api.RESTOptions) {
	result := DeleteSNICertificateResult{}
	resultByte, err := io.ReadAll(resp.Body)

	if err != nil {
		fmt.Printf("Error: Failed to read HTTP response: (%s)\n", err.Error())
		return
	}

	if err := json.Unmarshal(resultByte, &result); err != nil {
		fmt.Printf("Error: Failed to unmarshal HTTP response: (%s)\n", err.Error())
		return
	}

	if o.PrintOption == "json" {
		resultIndent, _ := json.MarshalIndent(result, "", "\t")
		fmt.Println(string(resultIndent))
		return
	}

	fmt.Printf("%s\n", result.Result)
}
