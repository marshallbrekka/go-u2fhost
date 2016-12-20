package u2f

import (
	"encoding/hex"
	"testing"
)

// Expected inputs and outputs are taken from the examples from the
// specification.
// https://fidoalliance.org/specs/fido-u2f-v1.0-nfc-bt-amendment-20150514/fido-u2f-raw-message-formats.html#examples
func TestRegisterRequest(t *testing.T) {
	cidPubKey := JSONWebKey{
		Algorithm: "EC",
		Curve:     "P-256",
		X:         "HzQwlfXX7Q4S5MtCCnZUNBw3RMzPO9tOyWjBqRl4tJ8",
		Y:         "XVguGFLIZx1fXg3wNqfdbn75hi4-_7-BxhMljw42Ht4",
	}

	clientDataHash := "4142d21c00d94ffb9d504ada8f99b721f4b191ae4e37ca0140f696b6983cfacb"
	appIdHash := "f0e6a6a97042a4f1f1c87f5f7d44315b2d852c2df5c7991cc66241bf7072d1c4"
	regRequest := &RegisterRequest{
		Challenge: "vqrS6WXDe1JUs5_c3i4-LkKIHRr-3XVb3azuA5TifHo",
		Facet:     "http://example.com",
		AppId:     "http://example.com",
	}
	expectedRequest := clientDataHash + appIdHash
	expectedJson := "{\"typ\":\"navigator.id.finishEnrollment\",\"challenge\":\"vqrS6WXDe1JUs5_c3i4-LkKIHRr-3XVb3azuA5TifHo\",\"cid_pubkey\":{\"kty\":\"EC\",\"crv\":\"P-256\",\"x\":\"HzQwlfXX7Q4S5MtCCnZUNBw3RMzPO9tOyWjBqRl4tJ8\",\"y\":\"XVguGFLIZx1fXg3wNqfdbn75hi4-_7-BxhMljw42Ht4\"},\"origin\":\"http://example.com\"}"
	clientJson, request := registerRequest(regRequest, cidPubKey)

	if string(clientJson) != expectedJson {
		t.Errorf("Expected client json to be %s but got %s", expectedJson, string(clientJson))
	}
	requestString := hex.EncodeToString(request)
	if requestString != expectedRequest {
		t.Errorf("Expected %s but got %s", expectedRequest, requestString)
	}
}

func TestAuthenticateRequest(t *testing.T) {
	keyHandle := "mykeyhandle"
	cidPubKey := JSONWebKey{
		Algorithm: "EC",
		Curve:     "P-256",
		X:         "HzQwlfXX7Q4S5MtCCnZUNBw3RMzPO9tOyWjBqRl4tJ8",
		Y:         "XVguGFLIZx1fXg3wNqfdbn75hi4-_7-BxhMljw42Ht4",
	}

	clientDataHash := "ccd6ee2e47baef244d49a222db496bad0ef5b6f93aa7cc4d30c4821b3b9dbc57"
	appIdHash := "4b0be934baebb5d12d26011b69227fa5e86df94e7d94aa2949a89f2d493992ca"
	authRequest := &AuthenticateRequest{
		Challenge: "opsXqUifDriAAmWclinfbS0e-USY0CgyJHe_Otd7z8o",
		Facet:     "http://example.com",
		AppId:     "https://gstatic.com/securitykey/a/example.com",
		KeyHandle: keyHandle,
	}
	expectedRequest := clientDataHash + appIdHash + hex.EncodeToString([]byte{11}) + hex.EncodeToString([]byte(keyHandle))
	expectedJson := "{\"typ\":\"navigator.id.getAssertion\",\"challenge\":\"opsXqUifDriAAmWclinfbS0e-USY0CgyJHe_Otd7z8o\",\"cid_pubkey\":{\"kty\":\"EC\",\"crv\":\"P-256\",\"x\":\"HzQwlfXX7Q4S5MtCCnZUNBw3RMzPO9tOyWjBqRl4tJ8\",\"y\":\"XVguGFLIZx1fXg3wNqfdbn75hi4-_7-BxhMljw42Ht4\"},\"origin\":\"http://example.com\"}"
	clientJson, request := authenticateRequest(authRequest, cidPubKey)

	if string(clientJson) != expectedJson {
		t.Errorf("Expected client json to be %s but got %s", expectedJson, string(clientJson))
	}
	requestString := hex.EncodeToString(request)
	if requestString != expectedRequest {
		t.Errorf("Expected %s but got %s", expectedRequest, requestString)
	}
}
