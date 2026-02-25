package commands

import (
	"github.com/ppiankov/awsspectre/internal/config"
	"github.com/ppiankov/awsspectre/internal/logging"
	"github.com/spf13/cobra"
	"log/slog"
)

var (
	verbose bool
	profile string
	version string
	commit  string
	date    string
	cfg     config.Config
)

var rootCmd = &cobra.Command{
	Use:   "awsspectre",
	Short: "awsspectre — AWS resource waste auditor",
	Long: `awsspectre finds idle, orphaned, and oversized AWS resources that cost money
for nothing. It scans EC2 instances, EBS volumes, Elastic IPs, load balancers,
NAT Gateways, RDS instances, snapshots, and security groups across all regions.

Each finding includes an estimated monthly waste in USD.`,
	PersistentPreRun: func(cmd *cobra.Command, args []string) {
		logging.Init(verbose)
		loaded, err := config.Load(".")
		if err != nil {
			slog.Warn("Failed to load config file", "error", err)
		} else {
			cfg = loaded
		}
	},
	SilenceUsage:  true,
	SilenceErrors: true,
}

// Execute runs the root command with injected build info.
func Execute(v, c, d string) error {
	version = v
	commit = c
	date = d
	return rootCmd.Execute()
}

func init() {
	rootCmd.PersistentFlags().BoolVar(&verbose, "verbose", false, "Enable verbose logging")
	rootCmd.PersistentFlags().StringVar(&profile, "profile", "", "AWS profile name")
	rootCmd.AddCommand(scanCmd)
	rootCmd.AddCommand(initCmd)
	rootCmd.AddCommand(versionCmd)
}
