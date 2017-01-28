package u2fhost

import "testing"

// Common resources for unit tests
// Some inputs and outputs are taken from the examples at the following url
// https://fidoalliance.org/specs/fido-u2f-v1.1-id-20160915/fido-u2f-raw-message-formats-v1.1-id-20160915.html#registration-example

var cidPubKey = JSONWebKey{
	Kty: "EC",
	Crv: "P-256",
	X:   "HzQwlfXX7Q4S5MtCCnZUNBw3RMzPO9tOyWjBqRl4tJ8",
	Y:   "XVguGFLIZx1fXg3wNqfdbn75hi4-_7-BxhMljw42Ht4",
}

// Implement hid.Device interface
type testDevice struct {
	// apdu request params
	instruction uint8
	p1          uint8
	p2          uint8
	request     []byte

	// apdu response elements
	status   uint16
	response []byte
	error    error

	// open error
	openError error
}

func newTestDevice() (*testDevice, *HidDevice) {
	testHid := &testDevice{}
	return testHid, newHidDevice(testHid)
}

func (d *testDevice) checkInputs(t *testing.T, instruction, p1, p2 uint8, request []byte) {
	if d.instruction != instruction {
		t.Errorf("Expected instruction %d, but got %d", instruction, d.instruction)
	}
	if d.p1 != p1 {
		t.Errorf("Expected p1 %d, but got %d", p1, d.p1)
	}
	if d.p2 != p2 {
		t.Errorf("Expected p2 %d, but got %d", p2, d.p2)
	}
	if string(d.request) != string(request) {
		t.Errorf("Expected request % x, but got % x", request, d.request)
	}
}

func (d *testDevice) Open() error {
	return d.openError
}

func (d *testDevice) Close() {}

func (d *testDevice) SendAPDU(instruction, p1, p2 uint8, data []byte) (uint16, []byte, error) {
	d.instruction = instruction
	d.p1 = p1
	d.p2 = p2
	d.request = data
	return d.status, d.response, d.error
}
