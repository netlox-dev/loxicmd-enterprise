package get

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

func NewGetSecurityRateCmd(restOptions *api.RESTOptions) *cobra.Command {
	var cmd = &cobra.Command{
		Use:     "securityrate",
		Short:   "Get unified security rate configuration and statistics",
		Aliases: []string{"security-rate", "rate_limit"},
		Long:    "Get unified security rate configuration and runtime statistics",
		Run: func(cmd *cobra.Command, args []string) {
			client := api.NewLoxiClient(restOptions)
			ctx := context.TODO()
			var cancel context.CancelFunc
			if restOptions.Timeout > 0 {
				ctx, cancel = context.WithTimeout(context.TODO(), time.Duration(restOptions.Timeout)*time.Second)
				defer cancel()
			}
			resp, err := client.SecurityRate().SetUrl("/config/securityrate/all").Get(ctx)
			if err != nil {
				fmt.Printf("Error: %s\n", err.Error())
				return
			}
			if resp.StatusCode == http.StatusOK {
				PrintGetSecurityRateResult(resp, *restOptions)
				return
			} else {
				fmt.Printf("Error: Unexpected status code %d\n", resp.StatusCode)
			}
		},
	}
	return cmd
}

func PrintGetSecurityRateResult(resp *http.Response, o api.RESTOptions) {
	var srResp api.SecurityRateInformationGet
	var data [][]string
	resultByte, err := io.ReadAll(resp.Body)
	if err != nil {
		fmt.Printf("Error: Failed to read HTTP response: (%s)\n", err.Error())
		return
	}

	if err := json.Unmarshal(resultByte, &srResp); err != nil {
		fmt.Printf("Error: Failed to unmarshal HTTP response: (%s)\n", err.Error())
		return
	}

	if o.PrintOption == "json" {
		resultIndent, _ := json.MarshalIndent(srResp, "", "    ")
		fmt.Println(string(resultIndent))
		return
	}

	table := TableInit()
	table.SetHeader([]string{"status", "synThreshold", "cookieThreshold", "connRate", "ratePerSec", "concurrentLimit", "udpEnabled", "udpPkt", "udpBW(MB)", "whitelist", "synBlocked", "synPassed", "connBlocked", "connPassed", "concurrentBlocked", "udpBlocked", "udpPassed", "uniqueIps"})

	for _, entry := range srResp.SecurityRateInfo {
		status := "disabled"
		if entry.SynEnabled {
			status = "enabled"
		}
		whitelist := "-"
		if len(entry.WhitelistIps) > 0 {
			whitelist = strings.Join(entry.WhitelistIps, ", ")
		}

		data = append(data, []string{
			status,
			fmt.Sprintf("%d", entry.SynThreshold),
			fmt.Sprintf("%d", entry.CookieThreshold),
			fmt.Sprintf("%t", entry.ConnRateEnabled),
			fmt.Sprintf("%d", entry.RatePerSec),
			fmt.Sprintf("%d", entry.ConcurrentLimit),
			fmt.Sprintf("%t", entry.UdpEnabled),
			fmt.Sprintf("%d", entry.UdpPktThreshold),
			fmt.Sprintf("%d", entry.UdpBandwidthMB),
			whitelist,
			fmt.Sprintf("%d", entry.SynBlocked),
			fmt.Sprintf("%d", entry.SynPassed),
			fmt.Sprintf("%d", entry.ConnBlocked),
			fmt.Sprintf("%d", entry.ConnPassed),
			fmt.Sprintf("%d", entry.ConcurrentBlocked),
			fmt.Sprintf("%d", entry.UdpBlocked),
			fmt.Sprintf("%d", entry.UdpPassed),
			fmt.Sprintf("%d", entry.UniqueIps),
		})
	}

	if len(data) == 0 {
		data = append(data, []string{"disabled", "-", "-", "false", "-", "-", "false", "-", "-", "-", "0", "0", "0", "0", "0", "0", "0", "0"})
	}

	TableShow(data, table)
}
