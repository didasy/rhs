# rhs
### Headache free encryption suite for golang
----------------------------------------------
[![GoDoc](https://godoc.org/github.com/JesusIslam/rhs?status.svg)](https://godoc.org/github.com/JesusIslam/rhs)

### What?
You want to send encrypted message or saving password into your database without having to bother to understand about how they works? Then this package is for you.

### Installation
`go get github.com/JesusIslam/rhs`

### Dependencies
```
go get golang.org/x/crypto/poly1305
go get golang.org/x/crypto/nacl
go get golang.org/x/crypto/scrypt
```

### Usage

If you want to store data, use *Store() methods. If not, use *Send() methods. 
Also do not ever forget to save your salt. Also, use different salt for key generation and encryption.
You need PKCS1 private key for RSA and prime256v1 EC for ECDSA private key in PEM format.

And just open `test/sample.go`

### Benchmark
Using i3-3217U @1.8GHz with `go test -bench . -cpu 4 -benchtime=5s`:
```
BenchmarkEncStoreNACL-4       50         124582774 ns/op
BenchmarkEncNACL-4         50000            122761 ns/op
BenchmarkEncStoreRSA-4        50         147158064 ns/op
BenchmarkEncRSA-4            200          27858745 ns/op
BenchmarkEncStoreECDSA-4      50         126524366 ns/op
BenchmarkEncECDSA-4         5000           1781388 ns/op
```

Yes, scrypt is slow (default N r p are 1 << 14, 8, and 1.) That's what makes it a better hashing algorithm.

### License
See LICENSE file, it is MIT