package main

import (
	"encoding/json"
	"fmt"
	log "github.com/Sirupsen/logrus"
	u2f "github.com/marshallbrekka/u2fhost"
	"github.com/spf13/cobra"
	"time"
)

var registerChallenge string
var registerAppId string
var registerFacet string

var registerCmd = &cobra.Command{
	Use:   "register",
	Short: "Register the U2F device.",
	Run: func(cmd *cobra.Command, args []string) {
		if registerChallenge == "" {
			log.Fatalf("Must specify challenge")
		}
		if registerAppId == "" {
			log.Fatalf("Must specify app id")
		}
		if registerFacet == "" {
			log.Fatalf("Must specify facet")
		}
		request := &u2f.RegisterRequest{
			Challenge: registerChallenge,
			AppId:     registerAppId,
			Facet:     registerFacet,
		}
		response := registerHelper(request, u2f.Devices())
		responseJson, _ := json.Marshal(response)
		fmt.Println(string(responseJson))
	},
}

func init() {
	RootCmd.AddCommand(registerCmd)
	registerCmd.Flags().StringVarP(&registerChallenge, "challenge", "c", "", "The registration challenge")
	registerCmd.Flags().StringVarP(&registerAppId, "app-id", "a", "", "App ID to register with")
	registerCmd.Flags().StringVarP(&registerFacet, "facet", "f", "", "The facet to register with")
}

func registerHelper(req *u2f.RegisterRequest, devices []*u2f.HidDevice) *u2f.RegisterResponse {
	log.Debugf("Registing with request %+v", req)
	openDevices := []u2f.Device{}
	for i, device := range devices {
		err := device.Open()
		if err == nil {
			openDevices = append(openDevices, devices[i])
			defer func(i int) {
				devices[i].Close()
			}(i)
			version, err := device.Version()
			if err != nil {
				log.Debugf("Device version error: %s", err)
			} else {
				log.Debugf("Device version: %s", version)
			}
		}
	}
	if len(openDevices) == 0 {
		log.Fatalf("Failed to find any devices")
	}
	fmt.Println("\nTouch the U2F device you wish to register...")
	iterationCount := 0
	for iterationCount < 100 {
		for _, device := range openDevices {
			response, err := device.Register(req)
			if err != nil {
				log.Debugf("Got error from device, skipping: %s", err.Error())
			} else {
				return response
			}
		}
		iterationCount += 1
		time.Sleep(250 * time.Millisecond)
	}
	log.Fatalf("Failed to get registration response after 25 seconds")
	return nil
}
