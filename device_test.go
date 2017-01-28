package u2fhost

import (
	"errors"
	"testing"
)

func TestOpen(t *testing.T) {
	testHid := &testDevice{}
	dev := newHidDevice(testHid)

	err := dev.Open()
	if err != nil {
		t.Fatalf("Unexpected error when opening device: %s", err)
	}

	openErr := errors.New("Open Error")
	testHid.openError = openErr

	err = dev.Open()
	if err == nil {
		t.Fatalf("Expected error when opening device")
	} else if err != openErr {
		t.Fatalf("Expected error %s but got %s", openErr, err)
	}
}

// Kind of pointless, but was easy to add
func TestClose(t *testing.T) {
	testHid := &testDevice{}
	dev := newHidDevice(testHid)

	dev.Close()
}

func TestVersion(t *testing.T) {
	// Happy path
	testHid := &testDevice{
		response: []byte("U2F_V2"),
		status:   u2fStatusNoError,
	}
	dev := newHidDevice(testHid)
	version, err := dev.Version()
	if err != nil {
		t.Errorf("Unexpected error getting version: %s", err)
	} else if version != "U2F_V2" {
		t.Errorf("Expected version U2F_V2 but got %s", version)
	}

	// Error from SendAPDU
	testHid.error = errors.New("APDU Error")
	version, err = dev.Version()
	if err == nil {
		t.Errorf("Expected error when getting version, but did not get one.")
	} else if err != testHid.error {
		t.Errorf("Expected error `%s` got `%s`", testHid.error, err)
	}

	// Error from status code
	testHid.error = nil
	testHid.status = u2fStatusCommandNotAllowed
	version, err = dev.Version()
	if err == nil {
		t.Errorf("Expected error when getting version, but did not get one.")
	} else if err.Error() != "U2FError: 0x6986" {
		t.Errorf("Expected error `U2FError: 0x6986` got `%s`", err)
	}
}
