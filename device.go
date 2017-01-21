package u2fhost

import (
	sha256pkg "crypto/sha256"
	b64 "encoding/base64"
	"encoding/json"
	"fmt"

	"github.com/marshallbrekka/u2fhost/hid"
)

// APDU Commands
const (
	u2fCommandRegister          uint8 = 0x01 // Registration command
	u2fCommandAuthenticate      uint8 = 0x02 // Authenticate/sign command
	u2fCommandVersion           uint8 = 0x03 // Read version string command
	u2fCommandCheckRegister     uint8 = 0x04 // Registration command that incorporates checking key handles
	u2fCommandAuthenticateBatch uint8 = 0x05 // Authenticate/sign command for a batch of key handles
)

// APDU Response Codes
const (
	u2fStatusNoError                uint16 = 0x9000
	u2fStatusWrongData              uint16 = 0x6A80
	u2fStatusConditionsNotSatisfied uint16 = 0x6985
	u2fStatusCommandNotAllowed      uint16 = 0x6986
	u2fStatusInsNotSupported        uint16 = 0x6D00
)

// Authentication control byte
const (
	u2fAuthEnforce   uint8 = 0x03 // Enforce user presence and sign
	u2fAuthCheckOnly uint8 = 0x07 // Check only
)

type HidDevice struct {
	hidDevice hid.Device
}

func newHidDevice(dev hid.Device) *HidDevice {
	return &HidDevice{
		hidDevice: dev,
	}
}

// Returns a list of supported U2F devices as HidDevice pointers.
// If no suported devices are found, the returned list is empty.
func Devices() []*HidDevice {
	hidDevices := hid.Devices()
	devices := make([]*HidDevice, len(hidDevices))
	for i, _ := range hidDevices {
		devices[i] = newHidDevice(hidDevices[i])
	}
	return devices
}

// Opens the device.
// Must be called before calling Register* or Authenticate*.
func (dev *HidDevice) Open() error {
	return dev.hidDevice.Open()
}

// Closes the device.
func (dev *HidDevice) Close() {
	dev.hidDevice.Close()
}

// Returns the U2F version the device supports.
func (dev *HidDevice) Version() (string, error) {
	status, response, err := dev.hidDevice.SendAPDU(u2fCommandVersion, 0, 0, []byte{})
	if err != nil {
		return "", err
	}
	if status != u2fStatusNoError {
		return "", u2ferror(status)
	}
	return string(response), nil
}

// Registers with the device using the RegisterRequest, returning a RegisterResponse.
func (dev *HidDevice) Register(req *RegisterRequest) (*RegisterResponse, error) {
	return dev.register(req, nil)
}

// Registers with the device using the RegisterRequest and a JSONWebKey, returning a RegisterResponse.
func (dev *HidDevice) RegisterWithJWK(req *RegisterRequest, jsonWebKey *JSONWebKey) (*RegisterResponse, error) {
	return dev.register(req, jsonWebKey)
}

// Registers with the device using the RegisterRequest and a JSON web
// key string, returning a RegisterResponse.
func (dev *HidDevice) RegisterWithJWKString(req *RegisterRequest, jsonWebKey string) (*RegisterResponse, error) {
	return dev.register(req, jsonWebKey)
}

// Authenticates with the device using the AuthenticateRequest,
// returning an AuthenticateResponse.
func (dev *HidDevice) Authenticate(req *AuthenticateRequest) (*AuthenticateResponse, error) {
	return dev.authenticate(req, nil)
}

// Authenticates with the device using the AuthenticateRequest and a JSONWebKey,
// returning an AuthenticateResponse.
func (dev *HidDevice) AuthenticateWithJWK(req *AuthenticateRequest, jsonWebKey *JSONWebKey) (*AuthenticateResponse, error) {
	return dev.authenticate(req, jsonWebKey)
}

// Authenticates with the device using the AuthenticateRequest and a
// JSON web key string, returning an AuthenticateResponse.
func (dev *HidDevice) AuthenticateWithJWKString(req *AuthenticateRequest, jsonWebKey string) (*AuthenticateResponse, error) {
	return dev.authenticate(req, jsonWebKey)
}

func (dev *HidDevice) register(req *RegisterRequest, jsonWebKey interface{}) (*RegisterResponse, error) {
	clientData, request := registerRequest(req, jsonWebKey)
	var p1 uint8 = 0x03
	var p2 uint8 = 0
	status, response, err := dev.hidDevice.SendAPDU(u2fCommandRegister, p1, p2, request)
	var registerResponse *RegisterResponse
	if err == nil {
		if status == u2fStatusNoError {
			registerResponse = &RegisterResponse{
				RegistrationData: websafeEncode(response),
				ClientData:       websafeEncode(clientData),
			}
		} else {
			err = u2ferror(status)
		}
	}
	return registerResponse, err
}

func registerRequest(req *RegisterRequest, jsonWebKey interface{}) ([]byte, []byte) {
	request := make([]byte, 64)
	client := clientData{
		Type:               "navigator.id.finishEnrollment",
		Challenge:          req.Challenge,
		Origin:             req.Facet,
		ChannelIdPublicKey: jsonWebKey,
	}

	clientJson, _ := json.Marshal(client)
	copy(request, sha256(clientJson))
	copy(request[32:64], sha256([]byte(req.AppId)))
	return []byte(clientJson), request
}

func (dev *HidDevice) authenticate(req *AuthenticateRequest, jsonWebKey interface{}) (*AuthenticateResponse, error) {
	clientData, request := authenticateRequest(req, jsonWebKey)
	authModifier := u2fAuthEnforce
	if req.CheckOnly {
		authModifier = u2fAuthCheckOnly
	}
	status, response, err := dev.hidDevice.SendAPDU(u2fCommandAuthenticate, authModifier, 0x00, request)
	var authenticateResponse *AuthenticateResponse
	if err == nil {
		if status == u2fStatusNoError {
			authenticateResponse = &AuthenticateResponse{
				KeyHandle:     req.KeyHandle,
				ClientData:    websafeEncode(clientData),
				SignatureData: websafeEncode(response),
			}
		} else {
			err = u2ferror(status)
		}
	}
	return authenticateResponse, err
}

func authenticateRequest(req *AuthenticateRequest, jsonWebKey interface{}) ([]byte, []byte) {
	keyLength := uint8(len(req.KeyHandle))
	request := make([]byte, 65+keyLength)
	client := clientData{
		Type:               "navigator.id.getAssertion",
		Challenge:          req.Challenge,
		Origin:             req.Facet,
		ChannelIdPublicKey: jsonWebKey,
	}
	clientJson, _ := json.Marshal(client)
	copy(request[0:32], sha256(clientJson))
	copy(request[32:64], sha256([]byte(req.AppId)))
	request[64] = keyLength
	copy(request[65:], []byte(req.KeyHandle))
	return []byte(clientJson), request
}

func websafeEncode(data []byte) string {
	return b64.RawURLEncoding.EncodeToString(data)
}

func sha256(data []byte) []byte {
	sha_256 := sha256pkg.New()
	sha_256.Write(data)
	return sha_256.Sum(nil)
}

func u2ferror(err uint16) error {
	if err == u2fStatusConditionsNotSatisfied {
		return &TestOfUserPresenceRequiredError{}
	} else if err == u2fStatusWrongData {
		return &BadKeyHandleError{}
	}
	return fmt.Errorf("U2FError: 0x%02x", err)
}
