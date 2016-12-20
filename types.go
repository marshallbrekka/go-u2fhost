package u2f

type Device interface {
	Open() error
	Close()
	Version() (string, error)
	Register(*RegisterRequest) (uint16, *RegisterResponse, error)
	RegisterWithJWK(*RegisterRequest, *JSONWebKey) (uint16, *RegisterResponse, error)
	RegisterWithJWKString(*RegisterRequest, string) (uint16, *RegisterResponse, error)
	Authenticate(*AuthenticateRequest) (uint16, *AuthenticateResponse, error)
	AuthenticateWithJWK(*AuthenticateRequest, *JSONWebKey) (uint16, *AuthenticateResponse, error)
	AuthenticateWithJWKString(*AuthenticateRequest, string) (uint16, *AuthenticateResponse, error)
}

type RegisterRequest struct {
	Challenge string
	AppId     string
	Facet     string
}

type AuthenticateRequest struct {
	Challenge string
	AppId     string
	Facet     string
	KeyHandle string
	CheckOnly bool
}

type JSONWebKey struct {
	Algorithm string `json:"kty"`
	Curve     string `json:"crv"`
	X         string `json:"x"`
	Y         string `json:"y"`
}

type RegisterResponse struct {
	RegistrationData string `json:"registrationData"`
	ClientData       string `json:"clientData"`
}

type AuthenticateResponse struct {
	KeyHandle     string `json:"keyHandle"`
	ClientData    string `json:"clientData"`
	SignatureData string `json:"signatureData"`
}

type clientData struct {
	Type               string      `json:"typ"`
	Challenge          string      `json:"challenge"`
	ChannelIdPublicKey interface{} `json:"cid_pubkey,omitempty"`
	Origin             string      `json:"origin"`
}
