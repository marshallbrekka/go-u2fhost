package u2fhost

import (
	"encoding/hex"
	"testing"
)

func TestRegister(t *testing.T) {
	var response *RegisterResponse
	var err error
	testHid, dev := newTestDevice()

	// Error case
	regRequest := sampleRegisterRequest()
	regRequest.ChannelIdUnused = true
	response, err = dev.Register(regRequest)
	if err == nil {
		t.Errorf("Expected error, but did not get one")
	}

	// Happy path
	testHid.response = []byte{1, 2, 3, 4}
	testHid.status = u2fStatusNoError
	regRequest = sampleRegisterRequest()
	response, err = dev.Register(regRequest)
	if err != nil {
		t.Errorf("Unexpected error calling Register: %s", err)
	} else {
		testHid.checkInputs(t, u2fCommandRegister, 0x03, 0, testRegisterRequest)
		expected := sampleRegisterResponse("AQIDBA", testRegisterClientDataJson)
		if expected != *response {
			t.Errorf("Expected response %#v, but got %#v", expected, *response)
		}
	}

	// Error status code
	testHid.response = []byte{1, 2, 3, 4}
	testHid.status = u2fStatusConditionsNotSatisfied
	regRequest = sampleRegisterRequest()
	response, err = dev.Register(regRequest)
	if err == nil {
		t.Errorf("Did not get error calling Register")
	} else if _, ok := err.(*TestOfUserPresenceRequiredError); !ok {
		t.Errorf("Expected TestOfUserPresenceRequiredError, but got %#v", err)
	}
}

// Sample values are taken from the U2F spec examples
// https://fidoalliance.org/specs/fido-u2f-v1.1-id-20160915/fido-u2f-raw-message-formats-v1.1-id-20160915.html#registration-example
var testRegisterClientDataJson = "{\"typ\":\"navigator.id.finishEnrollment\",\"challenge\":\"vqrS6WXDe1JUs5_c3i4-LkKIHRr-3XVb3azuA5TifHo\",\"cid_pubkey\":{\"kty\":\"EC\",\"crv\":\"P-256\",\"x\":\"HzQwlfXX7Q4S5MtCCnZUNBw3RMzPO9tOyWjBqRl4tJ8\",\"y\":\"XVguGFLIZx1fXg3wNqfdbn75hi4-_7-BxhMljw42Ht4\"},\"origin\":\"http://example.com\"}"
var testRegisterClientDataHash = "4142d21c00d94ffb9d504ada8f99b721f4b191ae4e37ca0140f696b6983cfacb"
var testRegisterAppId = "http://example.com"
var testRegisterAppIdHash = "f0e6a6a97042a4f1f1c87f5f7d44315b2d852c2df5c7991cc66241bf7072d1c4"
var testRegisterChallenge = "vqrS6WXDe1JUs5_c3i4-LkKIHRr-3XVb3azuA5TifHo"
var testRegisterRequest, _ = hex.DecodeString(testRegisterClientDataHash + testRegisterAppIdHash)

func sampleRegisterRequest() *RegisterRequest {
	return &RegisterRequest{
		Challenge:          testRegisterChallenge,
		Facet:              testRegisterAppId,
		AppId:              testRegisterAppId,
		ChannelIdPublicKey: &cidPubKey,
	}
}

func sampleRegisterResponse(registrationData, clientData string) RegisterResponse {
	return RegisterResponse{
		RegistrationData: registrationData,
		ClientData:       websafeEncode([]byte(clientData)),
	}
}
