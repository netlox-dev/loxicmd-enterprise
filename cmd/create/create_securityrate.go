package create

import (
	"context"
	"fmt"
	"loxicmd/pkg/api"
	"net/http"
	"strings"
	"time"

	"github.com/spf13/cobra"
)

type CreateSecurityRateOptions struct {
	SynEnabled      bool
	SynThreshold    uint32
	CookieThreshold uint32
	ConnRateEnabled bool
	RatePerSec      uint32
	ConcurrentLimit uint32
	UdpEnabled      bool
	UdpPktThreshold uint32
	UdpBandwidthMB  uint32
	WhitelistIPs    string
}

func NewCreateSecurityRateCmd(restOptions *api.RESTOptions) *cobra.Command {
	o := CreateSecurityRateOptions{}

	var cmd = &cobra.Command{
		Use:   "securityrate",
		Short: "Configure unified security rate limiting (SYN + conn + UDP)",
		Long:  "Configure unified security rate limiting (SYN flood + connection rate + UDP flood)",
		PreRun: func(cmd *cobra.Command, args []string) {
			// Nothing mandatory by default; API will validate.
		},
		Run: func(cmd *cobra.Command, args []string) {
			// Local validation: cookie < syn if both enabled
			if o.SynEnabled && o.CookieThreshold >= o.SynThreshold {
				fmt.Printf("Error: cookieThreshold (%d) must be less than synThreshold (%d)\n", o.CookieThreshold, o.SynThreshold)
				return
			}

			// Validate at least one protection is enabled
			if !o.SynEnabled && !o.ConnRateEnabled && !o.UdpEnabled {
				fmt.Printf("Error: At least one protection (synEnabled, connRateEnabled, or udpEnabled) must be enabled\n")
				return
			}

			// Parse whitelist
			var whitelist []string
			if o.WhitelistIPs != "" {
				whitelist = strings.Split(o.WhitelistIPs, ",")
				for i := range whitelist {
					whitelist[i] = strings.TrimSpace(whitelist[i])
				}
			}

			cfg := api.SecurityRateConfig{
				SynEnabled:      o.SynEnabled,
				SynThreshold:    o.SynThreshold,
				CookieThreshold: o.CookieThreshold,
				ConnRateEnabled: o.ConnRateEnabled,
				RatePerSec:      o.RatePerSec,
				ConcurrentLimit: o.ConcurrentLimit,
				UdpEnabled:      o.UdpEnabled,
				UdpPktThreshold: o.UdpPktThreshold,
				UdpBandwidthMB:  o.UdpBandwidthMB,
				WhitelistIps:    whitelist,
			}

			resp, err := SecurityRateAPICall(restOptions, cfg)
			if err != nil {
				fmt.Printf("Error: %s\n", err.Error())
				return
			}
			defer resp.Body.Close()

			fmt.Printf("Debug: response.StatusCode: %d\n", resp.StatusCode)
			if resp.StatusCode == http.StatusOK || resp.StatusCode == http.StatusNoContent {
				fmt.Printf("✅ Security rate configuration applied successfully\n")
				return
			}
			PrintCreateResult(resp, *restOptions)
		},
	}

	cmd.Flags().BoolVar(&o.SynEnabled, "synEnabled", true, "Enable SYN flood protection")
	cmd.Flags().Uint32Var(&o.SynThreshold, "synThreshold", 100, "SYN packets/sec threshold")
	cmd.Flags().Uint32Var(&o.CookieThreshold, "cookieThreshold", 50, "SYN cookie activation threshold")
	cmd.Flags().BoolVar(&o.ConnRateEnabled, "connRateEnabled", false, "Enable connection rate limiting")
	cmd.Flags().Uint32Var(&o.RatePerSec, "ratePerSec", 50, "Connection attempts per second")
	cmd.Flags().Uint32Var(&o.ConcurrentLimit, "concurrentLimit", 200, "Concurrent connections limit")
	cmd.Flags().BoolVar(&o.UdpEnabled, "udpEnabled", false, "Enable UDP flood protection")
	cmd.Flags().Uint32Var(&o.UdpPktThreshold, "udpPktThreshold", 1000, "UDP packets/sec threshold")
	cmd.Flags().Uint32Var(&o.UdpBandwidthMB, "udpBandwidthMB", 100, "UDP bandwidth MB/sec threshold")
	cmd.Flags().StringVar(&o.WhitelistIPs, "whitelistIps", "", "Comma-separated whitelist IPs (CIDR)")

	return cmd
}

func SecurityRateAPICall(restOptions *api.RESTOptions, cfg api.SecurityRateConfig) (*http.Response, error) {
	client := api.NewLoxiClient(restOptions)
	ctx := context.TODO()
	var cancel context.CancelFunc
	if restOptions.Timeout > 0 {
		ctx, cancel = context.WithTimeout(context.TODO(), time.Duration(restOptions.Timeout)*time.Second)
		defer cancel()
	}
	return client.SecurityRate().Create(ctx, cfg)
}
