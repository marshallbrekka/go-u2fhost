package main

import (
	"encoding/json"
	"fmt"
	"time"

	u2f "github.com/marshallbrekka/go-u2fhost"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

var authenticateChallenge string
var authenticateAppId string
var authenticateFacet string
var authenticateKeyHandle string

var authenticateCmd = &cobra.Command{
	Use:   "authenticate",
	Short: "Authenticate with the device",
	Run: func(cmd *cobra.Command, args []string) {
		if authenticateChallenge == "" {
			log.Fatalf("Must specify challenge")
		}
		if authenticateAppId == "" {
			log.Fatalf("Must specify app id")
		}
		if authenticateFacet == "" {
			log.Fatalf("Must specify facet")
		}
		if authenticateKeyHandle == "" {
			log.Fatalf("Must specify key handle")
		}
		request := &u2f.AuthenticateRequest{
			Challenge: authenticateChallenge,
			AppId:     authenticateAppId,
			Facet:     authenticateFacet,
			KeyHandle: authenticateKeyHandle,
		}
		response := authenticateHelper(request, u2f.Devices())
		responseJson, _ := json.Marshal(response)
		fmt.Println(string(responseJson))
	},
}

func init() {
	RootCmd.AddCommand(authenticateCmd)
	authenticateCmd.Flags().StringVarP(&authenticateChallenge, "challenge", "c", "", "The registration challenge")
	authenticateCmd.Flags().StringVarP(&authenticateAppId, "app-id", "a", "", "App ID to authenticate with")
	authenticateCmd.Flags().StringVarP(&authenticateFacet, "facet", "f", "", "The facet to authenticate with")
	authenticateCmd.Flags().StringVarP(&authenticateKeyHandle, "key-handle", "k", "", "The key handle to authenticate with")
}

func authenticateHelper(req *u2f.AuthenticateRequest, devices []*u2f.HidDevice) *u2f.AuthenticateResponse {
	log.Debugf("Authenticating with request %+v", req)
	openDevices := []u2f.Device{}
	for i, device := range devices {
		err := device.Open()
		if err == nil {
			openDevices = append(openDevices, u2f.Device(devices[i]))
			defer func(i int) {
				devices[i].Close()
			}(i)
			version, err := device.Version()
			if err != nil {
				log.Debugf("Device version error: %s", err.Error())
			} else {
				log.Debugf("Device version: %s", version)
			}
		}
	}
	if len(openDevices) == 0 {
		log.Fatalf("Failed to find any devices")
	}
	prompted := false
	timeout := time.After(time.Second * 25)
	interval := time.NewTicker(time.Millisecond * 250)
	defer interval.Stop()
	for {
		select {
		case <-timeout:
			fmt.Println("Failed to get authentication response after 25 seconds")
			return nil
		case <-interval.C:
			for _, device := range openDevices {
				response, err := device.Authenticate(req)
				if err == nil {
					return response
				} else if _, ok := err.(*u2f.TestOfUserPresenceRequiredError); ok && !prompted {
					fmt.Println("\nTouch the flashing U2F device to authenticate...")
					prompted = true
				} else {
					log.Debugf("Got status response %s", err)
				}
			}
		}
	}
	return nil
}
