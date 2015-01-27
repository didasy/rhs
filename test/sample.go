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