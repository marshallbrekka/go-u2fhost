package u2fhost

import (
	"encoding/json"
	"fmt"
)

// Authenticates with the device using the AuthenticateRequest,
// returning an AuthenticateResponse.
func (dev *HidDevice) Authenticate(req *AuthenticateRequest) (*AuthenticateResponse, error) {
	clientData, request, err := authenticateRequest(req)
	if err != nil {
		return nil, err
	}

	authModifier := u2fAuthEnforce
	if req.CheckOnly {
		authModifier = u2fAuthCheckOnly
	}
	status, response, err := dev.hidDevice.SendAPDU(u2fCommandAuthenticate, authModifier, 0x00, request)
	return authenticateResponse(status, response, clientData, req.KeyHandle, err)
}

func authenticateResponse(status uint16, response, clientData []byte, keyHandle string, err error) (*AuthenticateResponse, error) {
	var authenticateResponse *AuthenticateResponse
	if err == nil {
		if status == u2fStatusNoError {
			authenticateResponse = &AuthenticateResponse{
				KeyHandle:     keyHandle,
				ClientData:    websafeEncode(clientData),
				SignatureData: websafeEncode(response),
			}
		} else {
			err = u2ferror(status)
		}
	}
	return authenticateResponse, err
}

func authenticateRequest(req *AuthenticateRequest) ([]byte, []byte, error) {
	// Get jsonWebKey, if any
	jsonWebKey, err := getJSONWebToken(req.JSONWebKey, req.JSONWebKeyString)
	if err != nil {
		return nil, nil, err
	}

	// Construct the client json
	keyHandle, err := websafeDecode(req.KeyHandle)
	if err != nil {
		return []byte{}, []byte{}, fmt.Errorf("base64 key handle: %s", err)
	}
	client := clientData{
		Type:               "navigator.id.getAssertion",
		Challenge:          req.Challenge,
		Origin:             req.Facet,
		ChannelIdPublicKey: jsonWebKey,
	}
	clientJson, _ := json.Marshal(client)

	// Pack into byte array
	keyLength := uint8(len(keyHandle))
	request := make([]byte, 65+keyLength)
	copy(request[0:32], sha256(clientJson))
	copy(request[32:64], sha256([]byte(req.AppId)))
	request[64] = keyLength
	copy(request[65:], keyHandle)
	return []byte(clientJson), request, nil
}
