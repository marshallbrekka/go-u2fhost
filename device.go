package u2f

import (
	sha256pkg "crypto/sha256"
	b64 "encoding/base64"
	"encoding/json"
	"fmt"
	log "github.com/Sirupsen/logrus"
	"github.com/marshallbrekka/u2f-host/hid"
)

//APDU Instructions
const U2F_REGISTER uint8 = 0x01           // Registration command
const U2F_AUTHENTICATE uint8 = 0x02       // Authenticate/sign command
const U2F_VERSION uint8 = 0x03            // Read version string command
const U2F_CHECK_REGISTER uint8 = 0x04     // Registration command that incorporates checking key handles
const U2F_AUTHENTICATE_BATCH uint8 = 0x05 // Authenticate/sign command for a batch of key handles

//APDU Response Codes
const SW_NO_ERROR uint16 = 0x9000
const SW_WRONG_DATA uint16 = 0x6A80
const SW_CONDITIONS_NOT_SATISFIED uint16 = 0x6985
const SW_COMMAND_NOT_ALLOWED uint16 = 0x6986
const SW_INS_NOT_SUPPORTED uint16 = 0x6D00

// Authentication control byte
const AUTH_ENFORCE uint8 = 0x03    // Enforce user presence and sign
const AUTH_CHECK_ONLY uint8 = 0x07 // Check only
const AUTH_FLAG_TUP uint8 = 0x01   // Test of user presence set

type HidDevice struct {
	hidDevice hid.Device
}

func newHidDevice(dev hid.Device) *HidDevice {
	return &HidDevice{
		hidDevice: dev,
	}
}

func Devices() []*HidDevice {
	hidDevices := hid.Devices()
	devices := make([]*HidDevice, len(hidDevices))
	for i, _ := range hidDevices {
		devices[i] = newHidDevice(hidDevices[i])
	}
	return devices
}

func (dev *HidDevice) Open() error {
	return dev.hidDevice.Open()
}

func (dev *HidDevice) Close() {
	dev.hidDevice.Close()
}

func (dev *HidDevice) Version() (string, error) {
	status, response, err := dev.hidDevice.SendAPDU(U2F_VERSION, 0, 0, []byte{})
	if err != nil {
		return "", err
	}
	if status != SW_NO_ERROR {
		return "", u2ferror(status)
	}
	return string(response), nil
}

func (dev *HidDevice) Register(req *RegisterRequest) (uint16, *RegisterResponse, error) {
	return dev.register(req, nil)
}

func (dev *HidDevice) RegisterWithJWK(req *RegisterRequest, jsonWebKey *JSONWebKey) (uint16, *RegisterResponse, error) {
	return dev.register(req, jsonWebKey)
}

func (dev *HidDevice) RegisterWithJWKString(req *RegisterRequest, jsonWebKey string) (uint16, *RegisterResponse, error) {
	return dev.register(req, jsonWebKey)
}

func (dev *HidDevice) Authenticate(req *AuthenticateRequest) (uint16, *AuthenticateResponse, error) {
	return dev.authenticate(req, nil)
}

func (dev *HidDevice) AuthenticateWithJWK(req *AuthenticateRequest, jsonWebKey *JSONWebKey) (uint16, *AuthenticateResponse, error) {
	return dev.authenticate(req, jsonWebKey)
}

func (dev *HidDevice) AuthenticateWithJWKString(req *AuthenticateRequest, jsonWebKey string) (uint16, *AuthenticateResponse, error) {
	return dev.authenticate(req, jsonWebKey)
}

func (dev *HidDevice) register(req *RegisterRequest, jsonWebKey interface{}) (uint16, *RegisterResponse, error) {
	clientData, request := registerRequest(req, jsonWebKey)
	var p1 uint8 = 0x03
	var p2 uint8 = 0
	status, response, err := dev.hidDevice.SendAPDU(U2F_REGISTER, p1, p2, request)
	var registerResponse *RegisterResponse
	if err == nil && status == SW_NO_ERROR {
		keyLength := response[66]
		keyContents := response[67 : 67+keyLength]
		log.Debugf("Key Handle %s", websafeEncode(keyContents))
		registerResponse = &RegisterResponse{
			RegistrationData: websafeEncode(response),
			ClientData:       websafeEncode(clientData),
		}
	}
	return status, registerResponse, err
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

func (dev *HidDevice) authenticate(req *AuthenticateRequest, jsonWebKey interface{}) (uint16, *AuthenticateResponse, error) {
	clientData, request := authenticateRequest(req, jsonWebKey)
	authModifier := AUTH_ENFORCE
	if req.CheckOnly {
		authModifier = AUTH_CHECK_ONLY
	}
	status, response, err := dev.hidDevice.SendAPDU(U2F_AUTHENTICATE, authModifier, 0x00, request)
	var authenticateResponse *AuthenticateResponse
	if err == nil && status == SW_NO_ERROR {
		authenticateResponse = &AuthenticateResponse{
			KeyHandle:     req.KeyHandle,
			ClientData:    websafeEncode(clientData),
			SignatureData: websafeEncode(response),
		}
	}
	return status, authenticateResponse, err
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
	return fmt.Errorf("U2FError: 0x%02x", err)
}
