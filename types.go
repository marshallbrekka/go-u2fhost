package u2f

// A Device is the interface for performing registration and signing operations.
type Device interface {
	Open() error
	Close()
	Version() (string, error)
	Register(*RegisterRequest) (uint16, *RegisterResponse, error)
	RegisterWithJWK(*RegisterRequest, *JSONWebKey) (uint16, *RegisterResponse, error)
	RegisterWithJWKString(*RegisterRequest, string) (uint16, *RegisterResponse, error)
	Sign(*SignRequest) (uint16, *SignResponse, error)
	SignWithJWK(*SignRequest, *JSONWebKey) (uint16, *SignResponse, error)
	SignWithJWKString(*SignRequest, string) (uint16, *SignResponse, error)
}

// A RegisterRequest struct is used when attempting to register a new U2F device.
type RegisterRequest struct {
	// A random string which the new device will sign
	Challenge string
	// For more information on AppId and Facets see https://fidoalliance.org/specs/fido-u2f-v1.0-ps-20141009/fido-appid-and-facets-ps-20141009.html#the-appid-and-facetid-assertions
	AppId string
	Facet string
}

// A response from Register operation.
type RegisterResponse struct {
	// Base64 encoded registration data.
	RegistrationData string `json:"registrationData"`
	// Base64 encoded client data.
	ClientData string `json:"clientData"`
}

// A SignRequest struct is used when attempting to sign the challenge with a
// previously registered U2F device.
type SignRequest struct {
	// A string to sign. If used for authentication it should be a random string,
	// but could also be used to sign other kinds of data (ex: commit sha).
	Challenge string
	// For more information on AppId and Facets see https://fidoalliance.org/specs/fido-u2f-v1.0-ps-20141009/fido-appid-and-facets-ps-20141009.html#the-appid-and-facetid-assertions
	AppId string
	Facet string
	// The base64 encoded key handle that was returned in the RegistrationData field of the RegisterResponse.
	KeyHandle string
	// Optional boolean (defaults to false) that when true, will not attempt to
	// sign the challenge, and will only return a the statuses
	CheckOnly bool
}

type SignResponse struct {
	KeyHandle     string `json:"keyHandle"`
	ClientData    string `json:"clientData"`
	SignatureData string `json:"signatureData"`
}

type JSONWebKey struct {
	Kty string `json:"kty"`
	Crv string `json:"crv"`
	X   string `json:"x"`
	Y   string `json:"y"`
}

type clientData struct {
	Type               string      `json:"typ"`
	Challenge          string      `json:"challenge"`
	ChannelIdPublicKey interface{} `json:"cid_pubkey,omitempty"`
	Origin             string      `json:"origin"`
}

// Errors
