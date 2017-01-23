package bytes

func Concat(slices ...[]byte) []byte {
	var length int
	for _, s := range slices {
		length += len(s)
	}
	destination := make([]byte, length)
	return ConcatInto(destination, slices...)
}

func ConcatInto(destination []byte, slices ...[]byte) []byte {
	var offset int
	for _, slice := range slices {
		copy(destination[offset:], slice)
		offset += len(slice)
	}
	return destination
}
