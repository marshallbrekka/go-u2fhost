package main

import (
	"fmt"
	"os"

	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

var Verbose bool

var RootCmd = &cobra.Command{
	Use:   "u2fhost",
	Short: "CLI for interacting with U2F tokens.",
}

func Execute() {
	if err := RootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(-1)
	}
}

func init() {
	cobra.OnInitialize(initCli)
	RootCmd.PersistentFlags().BoolVarP(&Verbose, "verbose", "v", false, "Turn on verbose logging")
}

func initCli() {
	if Verbose {
		log.SetLevel(log.DebugLevel)
	} else {
		log.SetLevel(log.InfoLevel)
	}
}

func main() {
	if err := RootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(-1)
	}
}
