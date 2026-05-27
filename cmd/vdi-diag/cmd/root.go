// Package cmd provides the CLI commands for vdi-diag.
package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var cfgFile string

var rootCmd = &cobra.Command{
	Use:   "vdi-diag",
	Short: "VDI connectivity diagnostic and monitoring tool",
	Long: `vdi-diag is a professional diagnostic tool for troubleshooting
Virtual Desktop Infrastructure (VDI) connectivity issues. It probes all
network layers involved in ICA session establishment to identify where
failures occur.

Use 'vdi-diag diagnose' for on-demand checks or
'vdi-diag monitor' for continuous observation.`,
}

// Execute runs the root command.
func Execute() error {
	return rootCmd.Execute()
}

func init() {
	cobra.OnInitialize(initConfig)
	rootCmd.PersistentFlags().StringVar(&cfgFile, "config", "", "config file (default is ./vdi-diag.yaml)")
	rootCmd.PersistentFlags().BoolP("verbose", "v", false, "enable verbose output")
	_ = viper.BindPFlag("verbose", rootCmd.PersistentFlags().Lookup("verbose"))
}

func initConfig() {
	if cfgFile != "" {
		viper.SetConfigFile(cfgFile)
	} else {
		viper.SetConfigName("vdi-diag")
		viper.SetConfigType("yaml")
		viper.AddConfigPath(".")
		home, err := os.UserHomeDir()
		if err == nil {
			viper.AddConfigPath(home)
		}
	}

	viper.AutomaticEnv()

	if err := viper.ReadInConfig(); err == nil {
		if viper.GetBool("verbose") {
			fmt.Fprintf(os.Stderr, "Using config file: %s\n", viper.ConfigFileUsed())
		}
	}
}
