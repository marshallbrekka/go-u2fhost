package u2fhost

import (
	"encoding/json"
	"fmt"
)

// Registers with the device using the RegisterRequest, returning a RegisterResponse.
func (dev *HidDevice) Register(req *RegisterRequest) (*RegisterResponse, error) {
	clientData, request, err := registerRequest(req)
	if err != nil {
		return nil, err
	}
	var p1 uint8 = 0x03
	var p2 uint8 = 0
	status, response, err := dev.hidDevice.SendAPDU(u2fCommandRegister, p1, p2, request)
	return registerResponse(status, response, clientData, err)
}

func registerResponse(status uint16, response, clientData []byte, err error) (*RegisterResponse, error) {
	var registerResponse *RegisterResponse
	if err == nil {
		if status == u2fStatusNoError {
			registerResponse = &RegisterResponse{
				RegistrationData: websafeEncode(response),
				ClientData:       websafeEncode(clientData),
			}
		} else {
			err = u2ferror(status)
		}
	}
	return registerResponse, err
}

func registerRequest(req *RegisterRequest) ([]byte, []byte, error) {
	// Get jsonWebKey, if any
	jsonWebKey, err := getJSONWebToken(req.JSONWebKey, req.JSONWebKeyString)
	if err != nil {
		return nil, nil, err
	}

	// Construct the client json
	client := clientData{
		Type:               "navigator.id.finishEnrollment",
		Challenge:          req.Challenge,
		Origin:             req.Facet,
		ChannelIdPublicKey: jsonWebKey,
	}
	clientJson, err := json.Marshal(client)
	if err != nil {
		return nil, nil, fmt.Errorf("Error marshaling clientData to json: %s", err)
	}

	// Pack into byte array
	request := make([]byte, 64)
	copy(request, sha256(clientJson))
	copy(request[32:64], sha256([]byte(req.AppId)))
	return []byte(clientJson), request, nil
}
