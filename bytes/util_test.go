package bytes

import (
	"reflect"
	"testing"
)

func TestConcat(t *testing.T) {
	var result []byte

	// zero args
	result = Concat()
	if !reflect.DeepEqual(result, []byte{}) {
		t.Errorf("Expected empty byte array, but got %#v", result)
	}

	result = Concat([]byte{1, 2, 3})
	if !reflect.DeepEqual(result, []byte{1, 2, 3}) {
		t.Errorf("Expected %#v but got %#v", []byte{1, 2, 3}, result)
	}

	result = Concat([]byte{1, 2, 3}, []byte{4, 5}, []byte{6})
	if !reflect.DeepEqual(result, []byte{1, 2, 3, 4, 5, 6}) {
		t.Errorf("Expected %#v but got %#v", []byte{1, 2, 3, 4, 5, 6}, result)
	}
}

func TestConcatInto(t *testing.T) {
	var destination []byte
	var err error

	_, err = ConcatInto(nil)
	if err == nil {
		t.Errorf("Expected error because destination is nil")
	}

	// zero args
	destination = []byte{}
	destination, err = ConcatInto(destination)
	if err != nil {
		t.Errorf("Unexpected error: %s", err)
	} else if !reflect.DeepEqual(destination, []byte{}) {
		t.Errorf("Expected empty byte array, but got %#v", destination)
	}

	destination = make([]byte, 3)
	_, err = ConcatInto(destination, []byte{1, 2, 3})
	if err != nil {
		t.Errorf("Unexpected error: %s", err)
	} else if !reflect.DeepEqual(destination, []byte{1, 2, 3}) {
		t.Errorf("Expected %#v but got %#v", []byte{1, 2, 3}, destination)
	}

	destination = make([]byte, 6)
	_, err = ConcatInto(destination, []byte{1, 2, 3}, []byte{4, 5}, []byte{6})
	if err != nil {
		t.Errorf("Unexpected error: %s", err)
	} else if !reflect.DeepEqual(destination, []byte{1, 2, 3, 4, 5, 6}) {
		t.Errorf("Expected %#v but got %#v", []byte{1, 2, 3, 4, 5, 6}, destination)
	}

	// destination larger than provided slices
	destination = make([]byte, 6)
	_, err = ConcatInto(destination, []byte{1}, []byte{2, 3})
	if err != nil {
		t.Errorf("Unexpected error: %s", err)
	} else if !reflect.DeepEqual(destination, []byte{1, 2, 3, 0, 0, 0}) {
		t.Errorf("Expected %#v but got %#v", []byte{1, 2, 3, 0, 0, 0}, destination)
	}

	// destination smaller than provided slices
	destination = make([]byte, 2)
	_, err = ConcatInto(destination, []byte{1}, []byte{2, 3})
	if err == nil {
		t.Errorf("Expected error, but got result %#v", destination)
	}
}
