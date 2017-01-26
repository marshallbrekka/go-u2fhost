package u2fhost

import (
	"encoding/hex"
	"fmt"
	"testing"
)

func TestAuthenticateRequest(t *testing.T) {
	keyHandle := "mykeyhandle"
	cidPubKey := JSONWebKey{
		Kty: "EC",
		Crv: "P-256",
		X:   "HzQwlfXX7Q4S5MtCCnZUNBw3RMzPO9tOyWjBqRl4tJ8",
		Y:   "XVguGFLIZx1fXg3wNqfdbn75hi4-_7-BxhMljw42Ht4",
	}

	clientDataHash := "ccd6ee2e47baef244d49a222db496bad0ef5b6f93aa7cc4d30c4821b3b9dbc57"
	appIdHash := "4b0be934baebb5d12d26011b69227fa5e86df94e7d94aa2949a89f2d493992ca"
	authRequest := &AuthenticateRequest{
		Challenge:          "opsXqUifDriAAmWclinfbS0e-USY0CgyJHe_Otd7z8o",
		Facet:              "http://example.com",
		AppId:              "https://gstatic.com/securitykey/a/example.com",
		KeyHandle:          websafeEncode([]byte(keyHandle)),
		ChannelIdPublicKey: &cidPubKey,
	}
	expectedRequest := clientDataHash + appIdHash + hex.EncodeToString([]byte{11}) + hex.EncodeToString([]byte(keyHandle))
	expectedJson := "{\"typ\":\"navigator.id.getAssertion\",\"challenge\":\"opsXqUifDriAAmWclinfbS0e-USY0CgyJHe_Otd7z8o\",\"cid_pubkey\":{\"kty\":\"EC\",\"crv\":\"P-256\",\"x\":\"HzQwlfXX7Q4S5MtCCnZUNBw3RMzPO9tOyWjBqRl4tJ8\",\"y\":\"XVguGFLIZx1fXg3wNqfdbn75hi4-_7-BxhMljw42Ht4\"},\"origin\":\"http://example.com\"}"
	clientJson, request, err := authenticateRequest(authRequest)
	if err != nil {
		t.Errorf("Error constructing authenticate request: %s", err)
	}
	if string(clientJson) != expectedJson {
		t.Errorf("Expected client json to be %s but got %s", expectedJson, string(clientJson))
	}
	requestString := hex.EncodeToString(request)
	if requestString != expectedRequest {
		t.Errorf("Expected %s but got %s", expectedRequest, requestString)
	}
}

func TestAuthenticateResponse(t *testing.T) {
	var resp *AuthenticateResponse
	var err error

	// Expect to return the error passed in.
	newError := fmt.Errorf("Error")
	resp, err = authenticateResponse(u2fStatusNoError, []byte{}, []byte{}, "keyhandle", newError)
	if err == nil {
		t.Errorf("Expected an error, but got response %+v", resp)
	} else if err != newError {
		t.Errorf("Expected error %s, but got %s", newError, err)
	}

	// Expect a U2F error based on the status
	resp, err = authenticateResponse(u2fStatusConditionsNotSatisfied, []byte{}, []byte{}, "keyhandle", nil)
	if err == nil {
		t.Errorf("Expected an error, but got response %+v", resp)
	} else if _, ok := err.(*TestOfUserPresenceRequiredError); !ok {
		t.Errorf("Expected an error, but got response %+v", resp)
	}

	// Expect a valid response
	expectedResponse := AuthenticateResponse{
		KeyHandle:     "keyhandle",
		SignatureData: "AQIDBA",
		ClientData:    "BQYHCA",
	}
	resp, err = authenticateResponse(u2fStatusNoError, []byte{1, 2, 3, 4}, []byte{5, 6, 7, 8}, "keyhandle", nil)
	if err != nil {
		t.Errorf("Did not expect an error: %s", err)
	} else if *resp != expectedResponse {
		t.Errorf("Expected %+v, but got response %+v", expectedResponse, *resp)
	}
}
