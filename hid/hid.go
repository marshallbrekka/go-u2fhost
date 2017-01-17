package hid

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	log "github.com/Sirupsen/logrus"
	"github.com/marshallbrekka/go.hid"
	"io"
)

const TYPE_INIT uint8 = 0x80
const HID_RPT_SIZE uint16 = 64

const CMD_INIT uint8 = 0x06
const CMD_WINK uint8 = 0x08
const CMD_APDU uint8 = 0x03

const STAT_ERR uint8 = 0xbf

/** Interfaces **/

type BaseDevice interface {
	Open() error
	Close()
	Write([]byte) (int, error)
	ReadTimeout([]byte, int) (int, error)
}

type Device interface {
	Open() error
	Close()
	SendAPDU(instruction, p1, p2 uint8, data []byte) (uint16, []byte, error)
}

// Returns an array of available HID devices.
func Devices() []*HidDevice {
	u2fDevices := []*HidDevice{}
	devices, _ := hid.Enumerate(0x0, 0x0)
	for _, device := range devices {
		// need to add some custom code to get hid usage from linux.
		// use the firefox u2f extension codebase as a reference.
		// https://github.com/prefiks/u2f4moz/blob/master/c_src/libu2f-host/devs.c#L117-L142
		if device.UsagePage == 0xf1d0 && device.Usage == 1 {
			u2fDevices = append(u2fDevices, newHidDevice(newRawHidDevice(device)))
		}
	}
	return u2fDevices
}

type HidDevice struct {
	Device    BaseDevice
	channelId uint32
	// Use the crypto/rand reader directly so we can unit test
	randReader io.Reader
}

func newHidDevice(dev BaseDevice) *HidDevice {
	return &HidDevice{
		Device:     dev,
		channelId:  0xffffffff,
		randReader: rand.Reader,
	}
}

func (dev *HidDevice) Open() error {
	err := dev.Device.Open()
	if err != nil {
		return err
	}
	nonce := make([]byte, 8)
	_, err = io.ReadFull(dev.randReader, nonce)
	if err != nil {
		return err
	}
	channelId, err := initDevice(dev.Device, dev.channelId, nonce)
	if err != nil {
		return err
	}
	dev.channelId = channelId
	return nil
}

func (dev *HidDevice) Close() {
	dev.Device.Close()
	dev.channelId = 0xffffffff
}

func (dev *HidDevice) SendAPDU(instruction, p1, p2 uint8, data []byte) (uint16, []byte, error) {
	size := uint32(len(data))
	request := make([]byte, 9+size)
	// first byte is zero, skip
	request[1] = instruction
	request[2] = p1
	request[3] = p2
	copy(request[4:7], int24bytes(size))
	copy(request[7:7+size], data)
	request[7+size] = 0x04
	request[8+size] = 0x00
	log.Debugf("APDU request % X", request)
	resp, err := call(dev.Device, dev.channelId, CMD_APDU, request)
	log.Debugf("APDU response % X", resp)
	if err != nil {
		return 0, []byte{}, err
	}
	status := resp[len(resp)-2:]
	return bytesint16(status), resp[:len(resp)-2], nil
}

/** Helper Functions **/

func call(dev BaseDevice, channelId uint32, command uint8, data []byte) ([]byte, error) {
	err := sendRequest(dev, channelId, command, data)
	if err != nil {
		return make([]byte, 0), err
	}
	return readResponse(dev, channelId, command)
}

func sendRequest(dev BaseDevice, channelId uint32, command uint8, data []byte) error {
	log.Debugf("Sending HID request: channelId %#x, command %#x: data %x", channelId, command, data)
	fullRequest := make([]byte, HID_RPT_SIZE+1)
	request := fullRequest[1:]
	copy(request[0:4], int32bytes(channelId))
	request[4] = TYPE_INIT | command
	copy(request[5:7], int16bytes(uint16(len(data))))
	copyLength := min(uint16(len(data)), HID_RPT_SIZE-7)
	offset := copyLength
	var sequence uint8 = 0
	copy(request[7:HID_RPT_SIZE], data[0:copyLength])
	_, err := dev.Write(fullRequest)
	if err != nil {
		return err
	}
	for offset < uint16(len(data)) {
		fullRequest = make([]byte, 65)
		request = fullRequest[1:]
		copy(request[0:4], int32bytes(channelId))
		request[4] = 0x7f & sequence
		copyLength = min(uint16(len(data)-int(offset)), HID_RPT_SIZE-5)
		copy(request[5:HID_RPT_SIZE], data[offset:offset+copyLength])
		_, err := dev.Write(fullRequest)
		if err != nil {
			return err
		}
		sequence += 1
		offset += copyLength
	}
	return nil
}

func readResponse(dev BaseDevice, channelId uint32, command uint8) ([]byte, error) {
	header := make([]byte, 5)
	copy(header[:4], int32bytes(channelId))
	header[4] = TYPE_INIT | command
	response := make([]byte, HID_RPT_SIZE)
	for !bytes.Equal(header, response[:5]) {
		_, err := dev.ReadTimeout(response, 2000)
		if err != nil {
			return []byte{}, err
		}
		if bytes.Equal(response[:4], header[:4]) && response[4] == STAT_ERR {
			return make([]byte, 0), u2fhiderror(response[6])
		}
	}
	dataLength := bytesint16(response[5:7])
	data := make([]byte, dataLength)
	totalRead := min(dataLength, HID_RPT_SIZE-7)
	copy(data, response[7:7+totalRead])
	var sequence uint8 = 0
	for totalRead < dataLength {
		response = make([]byte, HID_RPT_SIZE)
		_, err := dev.ReadTimeout(response, 2000)
		if err != nil {
			return []byte{}, err
		}
		if !bytes.Equal(response[:4], header[:4]) {
			return []byte{}, errors.New("Wrong CID from device!")
		}
		if response[4] != (sequence & 0x7f) {
			return []byte{}, errors.New("Wrong SEQ from device!")
		}
		sequence += 1
		partLength := min(HID_RPT_SIZE-5, dataLength-totalRead)
		copy(data[totalRead:totalRead+partLength], response[5:5+partLength])
		totalRead += partLength
	}
	return data, nil
}

func initDevice(dev BaseDevice, channelId uint32, nonce []byte) (uint32, error) {
	resp, err := call(dev, channelId, CMD_INIT, nonce)
	if err != nil {
		return 0, err
	}
	for !bytes.Equal(resp[:8], nonce) {
		// fmt.Println("Wrong nonce, read again...")
		resp, err = readResponse(dev, channelId, CMD_INIT)
		if err != nil {
			return 0, err
		}
	}
	return binary.BigEndian.Uint32(resp[8:12]), nil
}

func int32bytes(i uint32) []byte {
	b := make([]byte, 4)
	binary.BigEndian.PutUint32(b, i)
	return b
}

func int24bytes(i uint32) []byte {
	b := make([]byte, 4)
	binary.BigEndian.PutUint32(b, i)
	return b[1:4]
}

func int16bytes(i uint16) []byte {
	b := make([]byte, 2)
	binary.BigEndian.PutUint16(b, i)
	return b
}

func bytesint16(b []byte) uint16 {
	return binary.BigEndian.Uint16(b)
}

func min(a uint16, b uint16) uint16 {
	if a > b {
		return b
	} else {
		return a
	}
}

func u2fhiderror(err uint8) error {
	return fmt.Errorf("U2FHIDError: 0x%02x", err)
}
