package u2fhost

// A Device is the interface for performing registration and authentication operations.
type Device interface {
	Open() error
	Close()
	Version() (string, error)
	Register(*RegisterRequest) (*RegisterResponse, error)
	Authenticate(*AuthenticateRequest) (*AuthenticateResponse, error)
}

// A RegisterRequest struct is used when attempting to register a new U2F device.
type RegisterRequest struct {
	// A random string which the new device will sign, this should be
	// provided by the server.
	Challenge string

	// The AppId can be provided by the server, but if not it should
	// be provided by the client.
	// For more information on AppId and Facets see https://fidoalliance.org/specs/fido-u2f-v1.0-ps-20141009/fido-appid-and-facets-ps-20141009.html#the-appid-and-facetid-assertions
	AppId string

	// The Facet should be provided by the client.
	// For more information on AppId and Facets see https://fidoalliance.org/specs/fido-u2f-v1.0-ps-20141009/fido-appid-and-facets-ps-20141009.html#the-appid-and-facetid-assertions
	Facet string

	// Optional JSONWebKey, mutually exclusive with JSONWebKeyString
	JSONWebKey *JSONWebKey

	// Optional JSONWebKey in string form, mutually exclusive with JSONWebKey
	JSONWebKeyString *string
}

// A response from a Register operation.
// The response fields are typically passed back to the server.
type RegisterResponse struct {
	// Base64 encoded registration data.
	RegistrationData string `json:"registrationData"`
	// Base64 encoded client data.
	ClientData string `json:"clientData"`
}

// An AuthenticateRequest is used when attempting to sign the challenge with a
// previously registered U2F device.
type AuthenticateRequest struct {
	// A string to sign. If used for authentication it should be a random string,
	// but could also be used to sign other kinds of data (ex: commit sha).
	Challenge string

	// The AppId can be provided by the server, but if not it should
	// be provided by the client.
	// For more information on AppId and Facets see https://fidoalliance.org/specs/fido-u2f-v1.0-ps-20141009/fido-appid-and-facets-ps-20141009.html#the-appid-and-facetid-assertions
	AppId string

	// The Facet should be provided by the client.
	// For more information on AppId and Facets see https://fidoalliance.org/specs/fido-u2f-v1.0-ps-20141009/fido-appid-and-facets-ps-20141009.html#the-appid-and-facetid-assertions
	Facet string

	// The base64 encoded key handle that was returned in the RegistrationData field of the RegisterResponse.
	KeyHandle string

	// Optional JSONWebKey, mutually exclusive with JSONWebKeyString
	JSONWebKey *JSONWebKey

	// Optional JSONWebKey in string form, mutually exclusive with JSONWebKey
	JSONWebKeyString *string

	// Optional boolean (defaults to false) that when true, will not attempt to
	// sign the challenge, and will only return a the statuses
	CheckOnly bool
}

// A response from an Authenticate operation.
// The response fields are typically passed back to the server.
type AuthenticateResponse struct {
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
