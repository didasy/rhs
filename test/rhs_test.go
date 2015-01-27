package main

import (
	"testing"
	"github.com/JesusIslam/rhs"
)

var key []byte = []byte("this is a key")
var password []byte = []byte("this is a password")

func BenchmarkEncStoreRSA(b *testing.B) {
	salt, err := rhs.GenSalt()
	if err != nil {
		panic(err)
	}
	err = rhs.SetKey(key, salt)
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
	for n := 0; n < b.N; n++ {
		_, _, _, err := e.EncryptRSAStore(password, salt, pk)
		if err != nil {
			panic(err)
		}
	}
}

func BenchmarkEncRSA(b *testing.B) {
	salt, err := rhs.GenSalt()
	if err != nil {
		panic(err)
	}
	err = rhs.SetKey(key, salt)
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
	for n := 0; n < b.N; n++ {
		_, _, _, err := e.EncryptRSASend(password, pk)
		if err != nil {
			panic(err)
		}
	}
}

func BenchmarkEncStoreECDSA(b *testing.B) {
	salt, err := rhs.GenSalt()
	if err != nil {
		panic(err)
	}
	err = rhs.SetKey(key, salt)
	if err != nil {
		panic(err)
	}
	e, err := rhs.New()
	if err != nil {
		panic(err)
	}
	pk, err := rhs.LoadPkECDSA("./ecpk.pem")
	if err != nil {
		panic(err)
	}
	for n := 0; n < b.N; n++ {
		_, _, _, _, err := e.EncryptECDSAStore(password, salt, pk)
		if err != nil {
			panic(err)
		}
	}
}

func BenchmarkEncECDSA(b *testing.B) {
	salt, err := rhs.GenSalt()
	if err != nil {
		panic(err)
	}
	err = rhs.SetKey(key, salt)
	if err != nil {
		panic(err)
	}
	e, err := rhs.New()
	if err != nil {
		panic(err)
	}
	pk, err := rhs.LoadPkECDSA("./ecpk.pem")
	if err != nil {
		panic(err)
	}
	for n := 0; n < b.N; n++ {
		_, _, _, _, err := e.EncryptECDSASend(password, pk)
		if err != nil {
			panic(err)
		}
	}
}