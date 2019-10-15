package hid

import (
	"bytes"
	"fmt"
	"testing"

	butil "github.com/marshallbrekka/go-u2fhost/bytes"
)

func TestOpen(t *testing.T) {
	// Test error handling for open
	baseDevice, dev := testDevice()
	baseDevice.openError = fmt.Errorf("open error")
	if dev.Open() == nil {
		t.Errorf("Expected error but got nil")
	}

	// Test error handling from rand reader
	baseDevice, dev = testDevice()
	dev.randReader = &errorReader{err: fmt.Errorf("Error from random")}
	if dev.Open() == nil {
		t.Errorf("Expected error but got nil")
	}

	// Test error handling when writing
	baseDevice, dev = testDevice()
	dev.randReader = bytes.NewBuffer([]byte{1, 2, 3, 4, 5, 6, 7, 8})
	baseDevice.writeError = fmt.Errorf("Error writing")
	if dev.Open() == nil {
		t.Errorf("Expected error but got nil")
	}

	// Test that the channel id is initialized correctly.
	baseDevice, dev = testDevice()
	dev.randReader = bytes.NewBuffer([]byte{1, 2, 3, 4, 5, 6, 7, 8})
	// output1 won't match the nonce 1,2,3,4,5,6,7,8
	output1 := []byte{0xff, 0xff, 0xff, 0xff, 0x86, 0, 12, 1, 2, 2, 2, 5, 6, 7, 8, 6, 7, 8, 9}
	// but output2 does
	output2 := []byte{0xff, 0xff, 0xff, 0xff, 0x86, 0, 12, 1, 2, 3, 4, 5, 6, 7, 8, 4, 5, 6, 7}
	spacer := make([]byte, 64-len(output1))
	baseDevice.output = butil.Concat(output1, spacer, output2, spacer)
	expectedInput, _ := butil.ConcatInto(make([]byte, 65), []byte{0, 0xff, 0xff, 0xff, 0xff, 0x86, 0, 8, 1, 2, 3, 4, 5, 6, 7, 8})

	// The uint32 of the bytes 4,5,6,7
	var expectedChannel uint32 = 67438087
	dev.Open()
	if !bytes.Equal(baseDevice.input, expectedInput) {
		t.Errorf("Expected input of %v but got %v", expectedInput, baseDevice.input)
	}
	if dev.channelId != expectedChannel {
		t.Errorf("Expected channel id %d but got %d", expectedChannel, dev.channelId)
	}
}

func TestClose(t *testing.T) {
	baseDevice := &testWrapperDevice{}
	dev := newHidDevice(baseDevice)
	// set to a channel id != to the initial id
	dev.channelId = 0x00000000
	dev.Close()
	// test that the channel id has been reset to the correct initial value
	if dev.channelId != 0xffffffff {
		t.Errorf("Expected channel id to equal 0xffffffff but instead got %#x", dev.channelId)
	}
}

func TestSendAPDU(t *testing.T) {
	baseDevice := &testWrapperDevice{}
	dev := newHidDevice(baseDevice)
	baseDevice.output, _ = butil.ConcatInto(make([]byte, 64), []byte{255, 255, 255, 255, 0x83, 0, 8, 85, 50, 70, 95, 86, 50, 0x90, 0x00})
	expectedInput, _ := butil.ConcatInto(make([]byte, 65), []byte{0, 255, 255, 255, 255, 0x83, 0, 12, 0, 0x03, 0, 0, 0, 0, 0x03, 1, 2, 3, 0x04, 0})
	status, result, err := dev.SendAPDU(0x03, 0, 0, []byte{1, 2, 3})
	if err != nil {
		t.Errorf("Did not expect error, but got %s", err.Error())
	}
	if status != 0x9000 {
		t.Errorf("Expected status 0x9000 but got %#x", status)
	}
	if string(result) != "U2F_V2" {
		t.Errorf("Expected result U2F_V2 but got %v", result)
	}
	if !bytes.Equal(expectedInput, baseDevice.input) {
		t.Errorf("Expected %v but got %v", expectedInput, baseDevice.input)
	}
}

// Test internal functions for edge cases.

func TestSendRequestError(t *testing.T) {
	// Test error handling
	writeError := fmt.Errorf("write error")
	dev := &testWrapperDevice{writeError: writeError}
	err := sendRequest(dev, 0, 1, []byte{1, 2, 3, 4, 5})
	if err == nil {
		t.Errorf("Expected error but got nil")
	}
}

func TestSendRequestShortValue(t *testing.T) {
	dev := &testWrapperDevice{}
	// First byte is report id 0x0, the next 4 are channel id, the next is the
	// command (0x80 | cmd), the next two are the length of the data, and the last
	// 5 are the data.
	expectedSub := []byte{0, 0, 0, 0, 4, 129, 0, 5, 1, 2, 3, 4, 5}
	expectedFull, _ := butil.ConcatInto(make([]byte, 65), expectedSub)
	err := sendRequest(dev, 4, 1, []byte{1, 2, 3, 4, 5})
	if err != nil {
		t.Errorf("Got unexpected error: %s", err.Error())
	}
	if !bytes.Equal(dev.input, expectedFull) {
		t.Errorf("Expeced %v but got %v", expectedFull, dev.input)
	}
}

func TestSendRequestLongValue(t *testing.T) {
	dev := &testWrapperDevice{}
	header1 := []byte{0, 0, 0, 0, 4, 129, 1, 0}
	header2 := []byte{0, 0, 0, 0, 4, 0}
	header3 := []byte{0, 0, 0, 0, 4, 1}
	header4 := []byte{0, 0, 0, 0, 4, 2}
	header5 := []byte{0, 0, 0, 0, 4, 3}
	data1 := makeRange(0, 57)
	data2 := makeRange(0, 59)
	data3 := makeRange(0, 22)
	expected, _ := butil.ConcatInto(make([]byte, 65*5), header1, data1, header2, data2, header3, data2, header4, data2, header5, data3)
	requestData := butil.Concat(data1, data2, data2, data2, data3)
	err := sendRequest(dev, 4, 1, requestData)
	if err != nil {
		t.Errorf("Got unexpected error: %s", err.Error())
	}
	if !bytes.Equal(dev.input, expected) {
		t.Errorf("Expeced %v but got %v", expected, dev.input)
	}
}

func TestReadResponseError(t *testing.T) {
	// Test error handling
	readError := fmt.Errorf("read error")
	dev := &testWrapperDevice{readError: readError}
	_, err := readResponse(dev, 0, 1)
	if err == nil {
		t.Errorf("Expected error but got nil")
	}

	// Test error code response
	subResponse := []byte{0, 0, 0, 4, 0xbf}
	response, _ := butil.ConcatInto(make([]byte, 64), subResponse)
	dev = &testWrapperDevice{output: response}
	_, err = readResponse(dev, 4, 1)
	if err == nil {
		t.Errorf("Expected error but got nil")
	}

	// Test bad CID
	subResponse1 := []byte{0, 0, 0, 4, 129, 0, 64}
	subResponse2 := []byte{0, 0, 0, 3, 0}
	response = make([]byte, 128)
	copy(response, subResponse1)
	copy(response[64:128], subResponse2)
	dev = &testWrapperDevice{output: response}
	_, err = readResponse(dev, 4, 1)
	if err == nil {
		t.Errorf("Expected error but got nil")
	}

	// Test bad sequence number
	subResponse1 = []byte{0, 0, 0, 4, 129, 0, 64}
	subResponse2 = []byte{0, 0, 0, 4, 1}
	response = make([]byte, 128)
	copy(response, subResponse1)
	copy(response[64:128], subResponse2)
	dev = &testWrapperDevice{output: response}
	_, err = readResponse(dev, 4, 1)
	if err == nil {
		t.Errorf("Expected error but got nil")
	}
}

func TestReadResponseShortValue(t *testing.T) {
	// First byte is report id 0x0, the next 4 are channel id, the next is the
	// command (0x80 | cmd), the next two are the length of the data, and the last
	// 5 are the data.
	expected := []byte{0, 0, 0, 4, 129, 0, 5, 1, 2, 3, 4, 5}
	output, _ := butil.ConcatInto(make([]byte, 64), expected)
	dev := &testWrapperDevice{output: output}

	response, err := readResponse(dev, 4, 1)
	if err != nil {
		t.Errorf("Got unexpected error: %s", err.Error())
	}
	if !bytes.Equal(expected[7:], response) {
		t.Errorf("Expeced %v but got %v", expected[7:], response)
	}
}

func TestReadResponseLongValue(t *testing.T) {
	header1 := []byte{0, 0, 0, 4, 129, 1, 0}
	header2 := []byte{0, 0, 0, 4, 0}
	header3 := []byte{0, 0, 0, 4, 1}
	header4 := []byte{0, 0, 0, 4, 2}
	header5 := []byte{0, 0, 0, 4, 3}
	data1 := makeRange(0, 57)
	data2 := makeRange(0, 59)
	data3 := makeRange(0, 22)

	expected := butil.Concat(data1, data2, data2, data2, data3)
	output, _ := butil.ConcatInto(make([]byte, 64*5), header1, data1, header2, data2, header3, data2, header4, data2, header5, data3)
	dev := &testWrapperDevice{output: output}

	response, err := readResponse(dev, 4, 1)
	if err != nil {
		t.Errorf("Got unexpected error: %s", err.Error())
	}
	if !bytes.Equal(response, expected) {
		t.Errorf("Expeced %v but got %v", expected, response)
	}
}

// make a slice of numbers between min (inclusive) and max (exclusive)
func makeRange(min, max byte) []byte {
	a := make([]byte, int(max)-int(min))
	var value byte = 0
	for i := range a {
		a[i] = value
		value++
	}
	return a
}

type testWrapperDevice struct {
	input       []byte
	output      []byte
	readPointer int
	openError   error
	readError   error
	writeError  error
}

func (dev *testWrapperDevice) Write(data []byte) (int, error) {
	if dev.writeError != nil {
		return 0, dev.writeError
	}
	dev.input = append(dev.input, data...)
	return len(data), nil
}

func (dev *testWrapperDevice) Read(result []byte) (int, error) {
	if dev.readError != nil {
		return 0, dev.readError
	}
	readLength := len(dev.output)
	copyLength := 0
	if readLength-dev.readPointer > int(HID_RPT_SIZE) {
		copyLength = int(HID_RPT_SIZE)
	} else {
		copyLength = readLength - dev.readPointer
	}
	copy(result[0:copyLength], dev.output[dev.readPointer:dev.readPointer+copyLength])
	dev.readPointer += copyLength
	return copyLength, nil
}

func (dev *testWrapperDevice) Open() error {
	return dev.openError
}

func (dev *testWrapperDevice) Close() {
}

// io.Reader that always returns an error
type errorReader struct {
	err error
}

func (r *errorReader) Read(b []byte) (int, error) {
	fmt.Println("returning error", r.err)
	return 0, r.err
}

func testDevice() (*testWrapperDevice, *HidDevice) {
	baseDevice := &testWrapperDevice{}
	return baseDevice, newHidDevice(baseDevice)
}
