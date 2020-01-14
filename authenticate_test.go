package u2fhost

import (
	"encoding/hex"
	"testing"
)

func TestAuthenticate(t *testing.T) {
	var response *AuthenticateResponse
	var err error
	testHid, dev := newTestDevice()

	// Error case
	authRequest := sampleAuthenticateRequest()
	authRequest.ChannelIdUnused = true
	response, err = dev.Authenticate(authRequest)
	if err == nil {
		t.Errorf("Expected error, but did not get one")
	}

	// Happy path
	testHid.response = []byte{1, 2, 3, 4, 5}
	testHid.status = u2fStatusNoError
	authRequest = sampleAuthenticateRequest()
	response, err = dev.Authenticate(authRequest)
	if err != nil {
		t.Errorf("Unexpected error calling Authenticate: %s", err)
	} else {
		testHid.checkInputs(t, u2fCommandAuthenticate, u2fAuthEnforce, 0, testAuthenticateRequest)
		expected := sampleAuthenticateResponse("AQIDBAU", testAuthenticateClientDataJson)
		if expected != *response {
			t.Errorf("Expected response %#v, but got %#v", expected, *response)
		}
	}

	// With auth modifier setting
	testHid.response = []byte{1, 2, 3, 4, 5}
	testHid.status = u2fStatusNoError
	authRequest = sampleAuthenticateRequest()
	authRequest.CheckOnly = true
	response, err = dev.Authenticate(authRequest)
	if err != nil {
		t.Errorf("Unexpected error calling Authenticate: %s", err)
	} else {
		testHid.checkInputs(t, u2fCommandAuthenticate, u2fAuthCheckOnly, 0, testAuthenticateRequest)
	}

	// With bad base64 encoded key handle
	testHid.response = []byte{1, 2, 3, 4, 5}
	testHid.status = u2fStatusNoError
	authRequest = sampleAuthenticateRequest()
	authRequest.KeyHandle = "i'm not base64 encoded correctly"
	response, err = dev.Authenticate(authRequest)
	if err == nil {
		t.Errorf("Expected base64 key handle error")
	}

	// Error status code
	testHid.response = []byte{1, 2, 3, 4, 5}
	testHid.status = u2fStatusConditionsNotSatisfied
	authRequest = sampleAuthenticateRequest()
	response, err = dev.Authenticate(authRequest)
	if err == nil {
		t.Errorf("Did not get error calling Register")
	} else if _, ok := err.(*TestOfUserPresenceRequiredError); !ok {
		t.Errorf("Expected TestOfUserPresenceRequiredError, but got %#v", err)
	}
}

// Sample values are taken from the U2F spec examples
// https://fidoalliance.org/specs/fido-u2f-v1.1-id-20160915/fido-u2f-raw-message-formats-v1.1-id-20160915.html#authentication-example
var testAuthenticateClientDataJson = "{\"typ\":\"navigator.id.getAssertion\",\"challenge\":\"opsXqUifDriAAmWclinfbS0e-USY0CgyJHe_Otd7z8o\",\"cid_pubkey\":{\"kty\":\"EC\",\"crv\":\"P-256\",\"x\":\"HzQwlfXX7Q4S5MtCCnZUNBw3RMzPO9tOyWjBqRl4tJ8\",\"y\":\"XVguGFLIZx1fXg3wNqfdbn75hi4-_7-BxhMljw42Ht4\"},\"origin\":\"http://example.com\"}"
var testAuthenticateClientDataHash = "ccd6ee2e47baef244d49a222db496bad0ef5b6f93aa7cc4d30c4821b3b9dbc57"
var testAuthenticateAppId = "https://gstatic.com/securitykey/a/example.com"
var testAuthenticateAppIdHash = "4b0be934baebb5d12d26011b69227fa5e86df94e7d94aa2949a89f2d493992ca"
var testAuthenticateChallenge = "opsXqUifDriAAmWclinfbS0e-USY0CgyJHe_Otd7z8o"
var testAuthenticateRequest, _ = hex.DecodeString(
	testAuthenticateClientDataHash +
		testAuthenticateAppIdHash +
		hex.EncodeToString([]byte{11}) +
		hex.EncodeToString([]byte("mykeyhandle")))

func sampleAuthenticateRequest() *AuthenticateRequest {
	return &AuthenticateRequest{
		Challenge:          testAuthenticateChallenge,
		Facet:              "http://example.com",
		AppId:              testAuthenticateAppId,
		KeyHandle:          websafeEncode([]byte("mykeyhandle")),
		ChannelIdPublicKey: &cidPubKey,
	}
}

func sampleAuthenticateResponse(signatureData, clientData string) AuthenticateResponse {
	return AuthenticateResponse{
		KeyHandle:     websafeEncode([]byte("mykeyhandle")),
		SignatureData: signatureData,
		ClientData:    websafeEncode([]byte(clientData)),
	}
}
