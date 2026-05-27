package cmd

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"
)

var configCmd = &cobra.Command{
	Use:   "config",
	Short: "Manage vdi-diag configuration",
}

var configInitCmd = &cobra.Command{
	Use:   "init",
	Short: "Create a default configuration file",
	RunE:  runConfigInit,
}

func init() {
	rootCmd.AddCommand(configCmd)
	configCmd.AddCommand(configInitCmd)
	configInitCmd.Flags().StringP("path", "p", ".", "directory to create config file in")
}

const defaultConfigContent = `# vdi-diag configuration file
# See: https://github.com/p2well/vdi-diag

targets:
  - name: vdi-gateway
    url: https://yourcompany.cloud.com
    ports:
      - 443   # HTTPS / TLS
      - 1494  # ICA
      - 2598  # CGP (Session Reliability)

monitoring:
  interval: 30s
  log_file: vdi-diag.log

alerts:
  latency_threshold_ms: 500
  consecutive_failures: 3
  packet_loss_percentage: 5

output:
  format: text

timeout: 10s
`

func runConfigInit(cmd *cobra.Command, args []string) error {
	dir, _ := cmd.Flags().GetString("path")
	configPath := filepath.Join(dir, "vdi-diag.yaml")

	if _, err := os.Stat(configPath); err == nil {
		return fmt.Errorf("config file already exists: %s", configPath)
	}

	if err := os.WriteFile(configPath, []byte(defaultConfigContent), 0644); err != nil {
		return fmt.Errorf("writing config file: %w", err)
	}

	fmt.Fprintf(os.Stderr, "✅ Created config file: %s\n", configPath)
	fmt.Fprintln(os.Stderr, "Edit the file to set your VDI gateway URL and preferences.")
	return nil
}
