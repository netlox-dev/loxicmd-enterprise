package delete

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"loxicmd/pkg/api"

	"github.com/spf13/cobra"
)

func NewDeleteSecurityRateCmd(restOptions *api.RESTOptions) *cobra.Command {
	var cmd = &cobra.Command{
		Use:   "securityrate",
		Short: "Disable unified security rate limiting",
		Long:  "Disable unified security rate limiting (SYN + connection rate + UDP flood)",
		Run: func(cmd *cobra.Command, args []string) {
			client := api.NewLoxiClient(restOptions)
			ctx := context.TODO()
			var cancel context.CancelFunc
			if restOptions.Timeout > 0 {
				ctx, cancel = context.WithTimeout(ctx, time.Duration(restOptions.Timeout)*time.Second)
				defer cancel()
			}

			resp, err := client.SecurityRate().Delete(ctx)
			if err != nil {
				fmt.Printf("Error: Failed to disable security rate: %s\n", err.Error())
				return
			}
			defer resp.Body.Close()

			fmt.Printf("Debug: response.StatusCode: %d\n", resp.StatusCode)
			if resp.StatusCode == http.StatusOK || resp.StatusCode == http.StatusNoContent {
				fmt.Printf("✅ Security rate disabled successfully\n")
				return
			} else {
				PrintDeleteResult(resp, *restOptions)
			}
		},
	}
	return cmd
}
