package u2fhost

import (
	sha256pkg "crypto/sha256"
	"encoding/base64"
	"fmt"
)

func websafeEncode(data []byte) string {
	return base64.RawURLEncoding.EncodeToString(data)
}

func websafeDecode(data string) ([]byte, error) {
	return base64.RawURLEncoding.DecodeString(data)
}

func sha256(data []byte) []byte {
	sha256Instance := sha256pkg.New()
	sha256Instance.Write(data)
	return sha256Instance.Sum(nil)
}

func getJSONWebToken(jwk *JSONWebKey, jwkString *string) (interface{}, error) {
	if jwk != nil && jwkString != nil {
		return nil, fmt.Errorf("Both JSONWebKey and JSONWebKeyString fields were supplied, but they are mutally exclusive.")
	}
	if jwk != nil {
		return jwk, nil
	}
	if jwkString != nil {
		return jwkString, nil
	}
	return nil, nil
}

func u2ferror(err uint16) error {
	if err == u2fStatusConditionsNotSatisfied {
		return &TestOfUserPresenceRequiredError{}
	} else if err == u2fStatusWrongData {
		return &BadKeyHandleError{}
	}
	return fmt.Errorf("U2FError: 0x%02x", err)
}
