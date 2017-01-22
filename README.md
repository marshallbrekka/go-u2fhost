# u2fhost
[![GoDoc](https://godoc.org/github.com/marshallbrekka/u2fhost?status.svg)](http://godoc.org/github.com/marshallbrekka/u2fhost) [![CircleCI](https://circleci.com/gh/marshallbrekka/u2fhost.svg?style=svg)](https://circleci.com/gh/marshallbrekka/u2fhost) 

A library for using U2F USB devices from Go programs.

## Who is this for
This library allows clients to interface with U2F USB devices to perform user authentication.

Because U2F is supported in most major browsers (either natively or by extensions), the only place I really forsee this being used (and why I wrote it in the first place) is to add U2F support to CLI apps.

## Usage

### Registration

To register with a new device, you will need to construct a `RegistrationRequest`.
```go
request := &RegisterRequest{
	// The challenge is provided by the server
	Challenge: "randomstringprovidedbyserver",
	// "The facet should be provided by the client making the request
	Facet:	 "https://example.com",
	// "The AppId may be provided by the server or the client client making the request.
	AppId:	 "https://example.com",
}
```

Next, get a list of devices that you can attempt to register with.

```go
allDevices := Devices()
// Filter only the devices that can be opened.
openDevices := []Device{}
for i, device := range devices {
	err := device.Open()
	if err == nil {
		openDevices = append(openDevices, devices[i])
		defer func(i int) {
			devices[i].Close()
		}(i)
	}
}
```

Once you have a slice of open devices, repeatedly call the `Register` function until the user activates a device, or you time out waiting for the user.

```go
// Prompt the user to perform the registration request.
fmt.Println("\nTouch the U2F device you wish to register...")
var response RegisterResponse
var err error
iterationCount := 0
for iterationCount < 100 {
	for _, device := range openDevices {
		response, err := device.Register(req)
		if err != nil {
			if _, ok := err.(TestOfUserPresenceRequiredError); ok {
				continue
			} else {
				// you should handle errors more gracefully than this
				panic(err)
			}
		} else {
			return response
		}
	}
	iterationCount += 1
	time.Sleep(250 * time.Millisecond)
}
```

Once you have a registration response, send the results back to your server in the form it expects.

### Authentication

To authenticate with a device, you will need to construct a `AuthenticateRequest`.

```go
request := &AuthenticateRequest{
	// The challenge is provided by the server
	Challenge: "randomstringprovidedbytheserver",
	 // "The facet should be provided by the client making the request
	Facet:	 authenticateFacet,
	// "The AppId may be provided by the server or the client client making the request.
	AppId:	 authenticateAppId,
	// The KeyHandle is provided by the server
	KeyHandle: string(keyHandle),
}
```

Next, get a list of devices that you can attempt to authenticate with.

```go
allDevices := Devices()
// Filter only the devices that can be opened.
openDevices := []Device{}
for i, device := range devices {
	err := device.Open()
	if err == nil {
		openDevices = append(openDevices, devices[i])
		defer func(i int) {
				devices[i].Close()
		}(i)
	}
}
```

Once you have a slice of open devices, repeatedly call the `Authenticate` function until the user activates a device, or you time out waiting for the user.

```go
iterationCount := 0
prompted := false
for iterationCount < 100 {
	for _, device := range openDevices {
		response, err := device.Authenticate(req)
		if err == nil {
			return response
			log.Debugf("Got error from device, skipping: %s", err.Error())
		} else if _, ok := err.(TestOfUserPresenceRequiredError); ok && !prompted {
			fmt.Println("\nTouch the flashing U2F device to authenticate...\n")
			prompted = true
		} else {
			fmt.Printf("Got status response %#x\n", err)
		}
	}
	iterationCount += 1
	time.Sleep(250 * time.Millisecond)
}
```
