package u2fhost

import (
	"reflect"
	"testing"
)

func TestChannelIdPublicKey(t *testing.T) {
	var cid interface{}
	var err error

	// cid and err should be nil
	cid, err = channelIdPublicKey(nil, false)
	if err != nil {
		t.Fatalf("Did not expect an error, but got %s", err)
	}
	if cid != nil {
		t.Fatalf("Expected cid to be nil, but got %+v", cid)
	}

	// cid should be "unused"
	cid, err = channelIdPublicKey(nil, true)
	if err != nil {
		t.Fatalf("Did not expect an error, but got %s", err)
	}
	cidString, ok := cid.(string)
	if !ok {
		t.Fatalf("Expected cid to be a string, but got %+v", cid)
	}
	if cidString != "unused" {
		t.Fatalf("Expected cid to equal \"unused\", but got %s", cidString)
	}

	// cid should be a JSONWebKey
	jwk := &JSONWebKey{
		Kty: "EC",
		Crv: "P-256",
		X:   "HzQwlfXX7Q4S5MtCCnZUNBw3RMzPO9tOyWjBqRl4tJ8",
		Y:   "XVguGFLIZx1fXg3wNqfdbn75hi4-_7-BxhMljw42Ht4",
	}
	cid, err = channelIdPublicKey(jwk, false)
	if err != nil {
		t.Fatalf("Did not expect an error, but got %s", err)
	}
	cidJwk, ok := cid.(*JSONWebKey)
	if !ok {
		t.Fatalf("Expected cid to be a JSONWebKey, but got %+v", cid)
	}
	if cidJwk != jwk {
		t.Fatalf("Expected cid to equal %+v, but got %+v", jwk, cidJwk)
	}

	// We should get an error
	cid, err = channelIdPublicKey(jwk, true)
	if err == nil {
		t.Fatalf("Expected an error, but got cid = %+v", cid)
	}
}

func TestU2ferror(t *testing.T) {
	var err error

	err = u2ferror(0x6985)
	if _, ok := err.(*TestOfUserPresenceRequiredError); !ok {
		t.Fatalf("Expected TestOfUserPresenceRequiredError, but got %s", reflect.TypeOf(err))
	}

	err = u2ferror(0x6A80)
	if _, ok := err.(*BadKeyHandleError); !ok {
		t.Fatalf("Expected BadKeyHandleError, but got %s", reflect.TypeOf(err))
	}

	err = u2ferror(0x6D00)
	if err.Error() != "U2FError: 0x6d00" {
		t.Fatalf("Expected error \"U2FError: 0x6d00\", but got \"%s\"", err)
	}
}
