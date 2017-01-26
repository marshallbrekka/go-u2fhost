package u2fhost

import (
	"encoding/hex"
	"fmt"
	"testing"
)

func TestRegister(t *testing.T) {
	var response *RegisterResponse
	var err error
	testHid := &testDevice{}
	dev := newHidDevice(testHid)

	// Error case
	regRequest := &RegisterRequest{
		Challenge: "vqrS6WXDe1JUs5_c3i4-LkKIHRr-3XVb3azuA5TifHo",
		Facet:     "http://example.com",
		AppId:     "http://example.com",
		// these two options are mutually exclusive, should cause an error
		ChannelIdPublicKey: &cidPubKey,
		ChannelIdUnused:    true,
	}

	response, err = dev.Register(regRequest)
	if err == nil {
		t.Errorf("Expected error, but did not get one")
	}

	// Happy path
	testHid.response = []byte{1, 2, 3, 4}
	testHid.status = u2fStatusNoError
	regRequest = &RegisterRequest{
		Challenge:          "vqrS6WXDe1JUs5_c3i4-LkKIHRr-3XVb3azuA5TifHo",
		Facet:              "http://example.com",
		AppId:              "http://example.com",
		ChannelIdPublicKey: &cidPubKey,
	}
	clientDataHash := "4142d21c00d94ffb9d504ada8f99b721f4b191ae4e37ca0140f696b6983cfacb"
	appIdHash := "f0e6a6a97042a4f1f1c87f5f7d44315b2d852c2df5c7991cc66241bf7072d1c4"
	expectedRequest := clientDataHash + appIdHash
	expectedJson := "{\"typ\":\"navigator.id.finishEnrollment\",\"challenge\":\"vqrS6WXDe1JUs5_c3i4-LkKIHRr-3XVb3azuA5TifHo\",\"cid_pubkey\":{\"kty\":\"EC\",\"crv\":\"P-256\",\"x\":\"HzQwlfXX7Q4S5MtCCnZUNBw3RMzPO9tOyWjBqRl4tJ8\",\"y\":\"XVguGFLIZx1fXg3wNqfdbn75hi4-_7-BxhMljw42Ht4\"},\"origin\":\"http://example.com\"}"
	response, err = dev.Register(regRequest)
	requestString := hex.EncodeToString(testHid.request)
	if requestString != expectedRequest {
		t.Errorf("Expected request %s, but got %s", expectedRequest, requestString)
	}

	if err != nil {
		t.Errorf("Unexpected error calling Register: %s", err)
	} else {
		expected := RegisterResponse{
			RegistrationData: "AQIDBA",
			ClientData:       websafeEncode([]byte(expectedJson)),
		}
		if expected != *response {
			t.Errorf("Expected response %#v, but got %#v", expected, *response)
		}
	}
}

// Expected inputs and outputs are taken from the examples from the
// specification.
// https://fidoalliance.org/specs/fido-u2f-v1.0-nfc-bt-amendment-20150514/fido-u2f-raw-message-formats.html#examples
func TestRegisterRequest(t *testing.T) {
	clientDataHash := "4142d21c00d94ffb9d504ada8f99b721f4b191ae4e37ca0140f696b6983cfacb"
	appIdHash := "f0e6a6a97042a4f1f1c87f5f7d44315b2d852c2df5c7991cc66241bf7072d1c4"
	regRequest := &RegisterRequest{
		Challenge:          "vqrS6WXDe1JUs5_c3i4-LkKIHRr-3XVb3azuA5TifHo",
		Facet:              "http://example.com",
		AppId:              "http://example.com",
		ChannelIdPublicKey: &cidPubKey,
	}
	expectedRequest := clientDataHash + appIdHash
	expectedJson := "{\"typ\":\"navigator.id.finishEnrollment\",\"challenge\":\"vqrS6WXDe1JUs5_c3i4-LkKIHRr-3XVb3azuA5TifHo\",\"cid_pubkey\":{\"kty\":\"EC\",\"crv\":\"P-256\",\"x\":\"HzQwlfXX7Q4S5MtCCnZUNBw3RMzPO9tOyWjBqRl4tJ8\",\"y\":\"XVguGFLIZx1fXg3wNqfdbn75hi4-_7-BxhMljw42Ht4\"},\"origin\":\"http://example.com\"}"
	clientJson, request, err := registerRequest(regRequest)
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

func TestRegisterResponse(t *testing.T) {
	var resp *RegisterResponse
	var err error

	// Expect to return the error passed in.
	newError := fmt.Errorf("Error")
	resp, err = registerResponse(u2fStatusNoError, []byte{}, []byte{}, newError)
	if err == nil {
		t.Fatalf("Expected an error, but got response %+v", resp)
	} else if err != newError {
		t.Fatalf("Expected error %s, but got %s", newError, err)
	}

	// Expect a U2F error based on the status
	resp, err = registerResponse(u2fStatusConditionsNotSatisfied, []byte{}, []byte{}, nil)
	if err == nil {
		t.Fatalf("Expected an error, but got response %+v", resp)
	} else if _, ok := err.(*TestOfUserPresenceRequiredError); !ok {
		t.Fatalf("Expected an error, but got response %+v", resp)
	}

	// Expect a valid response
	expectedResponse := RegisterResponse{
		RegistrationData: "AQIDBA",
		ClientData:       "BQYHCA",
	}
	resp, err = registerResponse(u2fStatusNoError, []byte{1, 2, 3, 4}, []byte{5, 6, 7, 8}, nil)
	if err != nil {
		t.Fatalf("Did not expect an error: %s", err)
	} else if *resp != expectedResponse {
		t.Fatalf("Expected %+v, but got response %+v", expectedResponse, *resp)
	}
}

var cidPubKey = JSONWebKey{
	Kty: "EC",
	Crv: "P-256",
	X:   "HzQwlfXX7Q4S5MtCCnZUNBw3RMzPO9tOyWjBqRl4tJ8",
	Y:   "XVguGFLIZx1fXg3wNqfdbn75hi4-_7-BxhMljw42Ht4",
}
