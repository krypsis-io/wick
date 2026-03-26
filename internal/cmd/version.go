package cmd

import (
	"fmt"

	"github.com/krypsis-io/wick/internal/version"
	"github.com/spf13/cobra"
)

func init() {
	rootCmd.AddCommand(versionCmd)
}

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Print the version of wick",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Printf("wick %s (commit: %s, built: %s)\n", version.Version, version.Commit, version.Date)
	},
}
