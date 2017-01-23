package u2fhost

import (
	"encoding/hex"
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
