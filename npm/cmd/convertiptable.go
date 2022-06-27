package main

import (
	"fmt"

	dataplane "github.com/Azure/azure-container-networking/npm/pkg/dataplane/debug"
	"github.com/spf13/cobra"
)

func newConvertIPTableCmd() *cobra.Command {
	convertIPtableCmd := &cobra.Command{
		Use:   "convertiptable",
		Short: "Get list of iptable's rules in JSON format",
		RunE: func(cmd *cobra.Command, args []string) error {
			iptableName, _ := cmd.Flags().GetString("table") // TODO this isn't an argument right now
			if iptableName == "" {
				iptableName = "filter"
			}
			npmCacheF, _ := cmd.Flags().GetString("cache-file")
			iptableSaveF, _ := cmd.Flags().GetString("iptables-file")
			c := &dataplane.Converter{}
			switch {
			case npmCacheF == "" && iptableSaveF == "":
				ipTableRulesRes, err := c.GetProtobufRulesFromIptable(iptableName)
				if err != nil {
					return fmt.Errorf("%w", err)
				}

				if err := prettyPrintIPTables(ipTableRulesRes); err != nil {
					return fmt.Errorf("error printing iptables: %w", err)
				}
			case npmCacheF != "" && iptableSaveF != "":
				ipTableRulesRes, err := c.GetProtobufRulesFromIptableFile(iptableName, npmCacheF, iptableSaveF)
				if err != nil {
					return fmt.Errorf("%w", err)
				}

				if err := prettyPrintIPTables(ipTableRulesRes); err != nil {
					return fmt.Errorf("error printing iptables from file: %w", err)
				}
			default:
				return errSpecifyBothFiles
			}
			return nil
		},
	}

	convertIPtableCmd.Flags().StringP("iptables-file", "i", "", "Set the iptable-save file path (optional, but required when using a cache file)")
	convertIPtableCmd.Flags().StringP("cache-file", "c", "", "Set the NPM cache file path (optional, but required when using an iptables file)")

	return convertIPtableCmd
}
