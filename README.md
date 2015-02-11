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
github.com/agl/ed25519
go get golang.org/x/crypto/nacl
go get golang.org/x/crypto/scrypt
```

### Usage

If you want to store data, use *Store() methods. If not, use *Send() methods. 
Also do not ever forget to save your salt. Also, use different salt for key generation and encryption.
You need PKCS1 private key for RSA and prime256v1 EC for ECDSA private key in PEM format.

And just open `test/sample.go`

### Benchmark
Using i3-3217U @1.8GHz with `go test -bench . -cpu 4 -benchtime=5s -benchmem`:
```
BBenchmarkEncPGP-4         50000            173015 ns/op            6666 B/op         49 allocs/op
BenchmarkEncStoreNACL-4       50         121961218 ns/op        17117676 B/op         27 allocs/op
BenchmarkEncNACL-4        100000            118769 ns/op             336 B/op          5 allocs/op
BenchmarkEncStoreRSA-4        50         145076528 ns/op        18412665 B/op       9516 allocs/op
BenchmarkEncRSA-4            200          28223672 ns/op         1153243 B/op       7931 allocs/op
BenchmarkEncStoreECDSA-4      50         123162064 ns/op        17137053 B/op        412 allocs/op
BenchmarkEncECDSA-4         5000           1750764 ns/op           23321 B/op        392 allocs/op
```

Yes, scrypt is slow (default N r p are 1 << 14, 8, and 1.) That's what makes it a better hashing algorithm.

### License
See LICENSE file, it is MIT