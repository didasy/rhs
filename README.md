# rhs
### Headache free encryption suite for golang
----------------------------------------------
[![GoDoc](https://godoc.org/github.com/JesusIslam/rhs?status.svg)](https://godoc.org/github.com/JesusIslam/rhs)

### What?
You want to send encrypted message or saving password into your database without having to bother to understand about how they works? Then this package is for you.

### Installation
`go get github.com/JesusIslam/rhs`

### Dependencies
`go get golang.org/x/crypto/scrypt`

### Usage

If you want to store data, use *Store() methods. If not, use *Send() methods. 
Also do not ever forget to save your salt. Also, use different salt for key generation and encryption.
You need PKCS1 private key for RSA and prime256v1 EC for ECDSA private key in PEM format.

```
package main

import (
	"fmt"
	"github.com/JesusIslam/rhs"
)

func main() {
	password := []byte("a password")
	salt, err := rhs.GenSalt()
	if err != nil {
		panic(err)
	}
	e, err := rhs.New()
	if err != nil {
		panic(err)
	}
	pk, err := rhs.LoadPkRSA("./pk.pem")
	if err != nil {
		panic(err)
	}
	h, s, nonce, err := e.EncryptRSAStore(password, salt, pk)
	if err != nil {
		panic(err)
	}
	pub, err := rhs.LoadPubRSA("./pub.pem")
	if err != nil {
		panic(err)
	}
	err = e.ValidateRSA(password, salt, h, s, nonce, pub)
	if err != nil {
		panic(err)
	}
	fmt.Println("RSA OK")

	ecpk, err := rhs.LoadPkECDSA("./ecpk.pem")
	if err != nil {
		panic(err)
	}
	h, r, ecs, nonce, err := e.EncryptECDSAStore(password, salt, ecpk)
	if err != nil {
		panic(err)
	}
	ecpub, err := rhs.LoadPubECDSA("./ecpub.pem")
	if err != nil {
		panic(err)
	}
	err = e.ValidateECDSA(password, salt, h, r, ecs, nonce, ecpub)
	if err != nil {
		panic(err)
	}
	fmt.Println("ECDSA OK")
}
```

Or just open `test/sample.go`

### Benchmark
Using i3-3217U @1.8GHz with `go test -bench . -cpu 4 -benchtime=5s`:
```
BenchmarkEncStoreRSA-4        50         142835260 ns/op
BenchmarkEncRSA-4            200          27943591 ns/op
BenchmarkEncStoreECDSA-4      50         129386378 ns/op
BenchmarkEncECDSA-4         3000           2125081 ns/op
```

Yes, scrypt is slow (default N r p are 1 << 14, 8, and 1.) That's what makes it a better hashing algorithm.

### License
See LICENSE file, it is MIT