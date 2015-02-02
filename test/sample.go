package main

import (
	"fmt"
	"errors"
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
	ser, err := rhs.NewNACL()
	if err != nil {
		panic(err)
	}
	cli, err := rhs.NewNACL()
	if err != nil {
		panic(err)
	}
	enc, mh, n, err := ser.Encrypt(password, &cli.Pub)
	if err != nil {
		panic(err)
	}
	_, ok := cli.Decrypt(enc, mh, &n, &ser.Pub)
	if ok == false {
		panic(errors.New("FAILED TO DECRYPT"))
	}
	ser.GenSharedKey(&cli.Pub)
	cli.GenSharedKey(&ser.Pub)
	enc, mh, n, err = ser.EncryptSK(password)
	if err != nil {
		panic(err)
	}
	_, ok = cli.DecryptSK(enc, mh, &n)
	if ok == false {
		panic(errors.New("FAILED TO DECRYPT USING SK"))
	}
	fmt.Println("NACL OK")
}