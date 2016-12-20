package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	log "github.com/Sirupsen/logrus"
	u2f "github.com/marshallbrekka/u2f-host"
	"github.com/spf13/cobra"
	"time"
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
		keyHandle, err := base64.RawURLEncoding.DecodeString(authenticateKeyHandle)
		if err != nil {
			log.Fatalf("Got error decoding hex encoded key handle: %s", err.Error())
		}
		request := &u2f.AuthenticateRequest{
			Challenge: authenticateChallenge,
			AppId:     authenticateAppId,
			Facet:     authenticateFacet,
			KeyHandle: string(keyHandle),
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
			openDevices = append(openDevices, devices[i])
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
	iterationCount := 0
	prompted := false
	for iterationCount < 100 {
		for _, device := range openDevices {
			status, response, err := device.Authenticate(req)
			if err != nil {
				log.Debugf("Got error from device, skipping: %s", err.Error())
			}
			if status == u2f.SW_CONDITIONS_NOT_SATISFIED && !prompted {
				fmt.Println("\nTouch the flashing U2F device to authenticate...\n")
				prompted = true
			} else if status == u2f.SW_NO_ERROR {
				return response
			}
			log.Debugf("Got status response %#x", status)
		}
		iterationCount += 1
		time.Sleep(250 * time.Millisecond)
	}
	log.Fatalf("Failed to get authentication response after 25 seconds")
	return nil
}
