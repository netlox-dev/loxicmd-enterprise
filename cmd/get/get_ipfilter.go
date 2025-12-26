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
	"errors"
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

func NewGetIPFilterCmd(restOptions *api.RESTOptions) *cobra.Command {
	var GetIPFilterCmd = &cobra.Command{
		Use:     "ipfilter",
		Short:   "Get IP filter rules",
		Aliases: []string{"IPFilter", "ipf", "ip-filter"},
		Long:    `Display IP whitelist/blacklist filter rules with statistics`,
		Run: func(cmd *cobra.Command, args []string) {
			client := api.NewLoxiClient(restOptions)
			ctx := context.TODO()
			var cancel context.CancelFunc
			if restOptions.Timeout > 0 {
				ctx, cancel = context.WithTimeout(context.TODO(), time.Duration(restOptions.Timeout)*time.Second)
				defer cancel()
			}
			resp, err := client.IPFilter().SetUrl("/config/ipfilter/all").Get(ctx)
			if err != nil {
				fmt.Printf("Error: %s\n", err.Error())
				return
			}
			if resp.StatusCode == http.StatusOK {
				PrintGetIPFilterResult(resp, *restOptions)
				return
			}
		},
	}

	return GetIPFilterCmd
}

func PrintGetIPFilterResult(resp *http.Response, o api.RESTOptions) {
	ipfresp := api.IPFilterInformationGet{}
	var data [][]string
	resultByte, err := io.ReadAll(resp.Body)
	if err != nil {
		fmt.Printf("Error: Failed to read HTTP response: (%s)\n", err.Error())
		return
	}

	if err := json.Unmarshal(resultByte, &ipfresp); err != nil {
		fmt.Printf("Error: Failed to unmarshal HTTP response: (%s)\n", err.Error())
		return
	}

	// if json options enable, it print as a json format.
	if o.PrintOption == "json" {
		resultIndent, _ := json.MarshalIndent(ipfresp, "", "    ")
		fmt.Println(string(resultIndent))
		return
	}

	ipfresp.Sort()

	// Table Init
	table := TableInit()

	// Table header
	table.SetHeader(IPFILTER_TITLE)

	// Making IP filter data
	for _, ipfrule := range ipfresp.IPFilterInfo {
		data = append(data, []string{
			ipfrule.IPPrefix,
			ipfrule.Action,
			fmt.Sprintf("%d", ipfrule.Zone),
			fmt.Sprintf("%d", ipfrule.Priority),
			fmt.Sprintf("%d", ipfrule.Packets),
			fmt.Sprintf("%d", ipfrule.Bytes),
		})
	}

	// Rendering the IP filter data to table
	TableShow(data, table)
}

func IPFilterAPICall(restOptions *api.RESTOptions) (*http.Response, error) {
	client := api.NewLoxiClient(restOptions)
	ctx := context.TODO()
	var cancel context.CancelFunc
	if restOptions.Timeout > 0 {
		ctx, cancel = context.WithTimeout(context.TODO(), time.Duration(restOptions.Timeout)*time.Second)
		defer cancel()
	}
	resp, err := client.IPFilter().SetUrl("/config/ipfilter/all").Get(ctx)
	if err != nil {
		fmt.Printf("Error: %s\n", err.Error())
		return nil, err
	}
	return resp, nil
}

func IPFilterdump(restOptions *api.RESTOptions, path string) (string, error) {
	// File Open
	fileP := []string{"/tmp/IPFilterconfig_", ".txt"}
	t := time.Now()
	file := strings.Join(fileP, t.Local().Format("2006-01-02_15:04:05"))
	f, err := os.Create(file)
	if err != nil {
		fmt.Printf("Can't create dump file\n")
		os.Exit(1)
	}
	defer os.Remove(f.Name())

	// API Call
	client := api.NewLoxiClient(restOptions)
	ctx := context.TODO()
	var cancel context.CancelFunc
	if restOptions.Timeout > 0 {
		ctx, cancel = context.WithTimeout(context.TODO(), time.Duration(restOptions.Timeout)*time.Second)
		defer cancel()
	}
	resp, err := client.IPFilter().SetUrl("/config/ipfilter/all").Get(ctx)
	if err != nil {
		fmt.Printf("Error: %s\n", err.Error())
		return "", err
	}
	resultByte, err := io.ReadAll(resp.Body)
	if err != nil {
		fmt.Printf("Error: Failed to read HTTP response: (%s)\n", err.Error())
	}
	// Write
	f.Write(resultByte)

	cfile := path + "IPFilterconfig.txt"
	if _, err := os.Stat(cfile); errors.Is(err, os.ErrNotExist) {
		if err != nil {
			fmt.Println("There is no saved config file")
		}
	} else {
		command := "mv " + cfile + " " + cfile + ".bk"
		cmd := exec.Command("bash", "-c", command)
		_, err := cmd.Output()
		if err != nil {
			fmt.Println("Can't backup ", cfile)
			return file, err
		}
	}
	command := "cp -R " + file + " " + cfile
	cmd := exec.Command("bash", "-c", command)
	fmt.Println(cmd)
	_, err = cmd.Output()
	if err != nil {
		fmt.Println("Failed copy file to", cfile)
		return file, err
	}
	return file, nil
}
