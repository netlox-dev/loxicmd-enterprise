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
package create

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

type CreateSNICertificateOptions struct {
	Hostname string
	CertPath string
}

type CreateSNICertificateResult struct {
	Result string `json:"result"`
}

const CreateSNICertificateSuccess = "success"

func ReadCreateSNICertificateOptions(o *CreateSNICertificateOptions, args []string) error {
	if len(args) > 1 {
		return errors.New("create sni command has too many args")
	} else if len(args) < 1 {
		return errors.New("create sni needs HOSTNAME arg")
	}

	if args[0] == "" {
		return errors.New("hostname cannot be empty")
	}
	o.Hostname = args[0]

	return nil
}

func NewCreateSNICertificateCmd(restOptions *api.RESTOptions) *cobra.Command {
	o := CreateSNICertificateOptions{}

	var createSNICmd = &cobra.Command{
		Use:   "sni HOSTNAME [--cert-path=<path>]",
		Short: "Register SNI certificate globally",
		Long: `Register an SNI certificate globally that can be shared by all proxies.

The certificate files must be deployed to the filesystem before registration:
  Default path: /opt/loxilb/cert/{hostname}/server.crt and server.key
  Custom path: Specify with --cert-path option

The certificate will be automatically used by all loadbalancer rules with matching 'host' field.

Examples:
  loxicmd create sni api.example.com
  loxicmd create sni web.example.com --cert-path=/custom/path/
`,
		PreRun: func(cmd *cobra.Command, args []string) {
			// Validation handled in Run
		},
		Run: func(cmd *cobra.Command, args []string) {
			if err := ReadCreateSNICertificateOptions(&o, args); err != nil {
				fmt.Println(err)
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
				Hostname: &o.Hostname,
			}

			if o.CertPath != "" {
				sniModel.CertPath = o.CertPath
			}

			resp, err := client.SNICertificate().Create(ctx, sniModel)
			if err != nil {
				fmt.Printf("Error: Failed to register SNI certificate (Hostname: %s): %s\n",
					o.Hostname, err.Error())
				return
			}
			defer resp.Body.Close()

			fmt.Printf("Debug: response.StatusCode: %d\n", resp.StatusCode)
			if resp.StatusCode == http.StatusOK {
				PrintCreateSNIResult(resp, *restOptions)
				return
			}

			// Handle non-OK responses
			resultByte, _ := io.ReadAll(resp.Body)
			fmt.Printf("Error: Failed to register SNI certificate: %s\n", string(resultByte))
		},
	}

	createSNICmd.Flags().StringVarP(&o.CertPath, "cert-path", "", "", "Custom path to certificate files (optional)")

	return createSNICmd
}

func PrintCreateSNIResult(resp *http.Response, o api.RESTOptions) {
	result := CreateSNICertificateResult{}
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
