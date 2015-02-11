package rhs

import (
	"hash"
	"errors"
	"math/big"
	"io/ioutil"
	"encoding/pem"
	"crypto/aes"
	"crypto/rand"
	"crypto/x509"
	"crypto/rsa"
	"crypto/ecdsa"
	"crypto/cipher"
	"crypto/subtle"
	"crypto/sha256"
	"crypto/sha512"
	"github.com/agl/ed25519"
	"golang.org/x/crypto/scrypt"
	"golang.org/x/crypto/nacl/box"
	"golang.org/x/crypto/nacl/secretbox"
)

const (
	VERSION = "0.0.3"
)

// AES key, length must be 32 bytes to use AES256
var KEY []byte = []byte("change me from this 2 other byte")

// Additional data for AEAD
var DATA []byte = []byte("additional data")

// Salt must be the same when you encrypt and verify.
// Forgot to save salt means your data would be lost forever.
func GenSalt() ([]byte, error) {
	salt := make([]byte, 32)
	_, err := rand.Read(salt)
	if err != nil {
		return []byte{}, err
	}
	return salt, nil
}

// It is recommended if you set the key via this function rather than changing KEY directly.
// Please do not remember to save the salt.
func SetKey(key, salt []byte) error {
	K, err := scrypt.Key(key, salt, 1 << 14, 8, 1, 32)
	if err != nil {
		return err
	}
	KEY = K
	return nil
}

// Set additional data for AEAD
func SetData(data []byte) {
	DATA = data
}

type ENC struct {
	GCM cipher.AEAD
}

// Create new encrypter 
func New() (*ENC, error) {
	b, err := aes.NewCipher(KEY)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(b)
	if err != nil {
		return nil, err
	}
	return &ENC{aead}, nil
}

// Load ECDSA private key, pk's EC must be prime256v1
func LoadPkECDSA(path string) (*ecdsa.PrivateKey, error) {
	// load pem from file
	pemData, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, err
	}
	// extract PEM-encoded data block
	block, _ := pem.Decode(pemData)
	if block == nil {
		return nil, errors.New("Bad key data")
	}
	if block.Type != "EC PRIVATE KEY" {
		return nil, errors.New("Unknown key type")
	}
	// Decode the ECDSA private key
	pk, err := x509.ParseECPrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	return pk, nil
}

// Load RSA private key, pk must be PKCS1 and at least 2048 bits
func LoadPkRSA(path string) (*rsa.PrivateKey, error) {
	// load pem from file
	pemData, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, err
	}
	// extract PEM-encoded data block
	block, _ := pem.Decode(pemData)
	if block == nil {
		return nil, errors.New("Bad key data")
	}
	if block.Type != "RSA PRIVATE KEY" {
		return nil, errors.New("Unknown key type")
	}
	// Decode the RSA private key
	pk, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	pk.Precompute()
	err = pk.Validate()
	if err != nil {
		return nil, err
	}

	return pk, nil
}

// Load ECDSA public key
func LoadPubECDSA(path string) (*ecdsa.PublicKey, error) {
	pemData, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, err
	}
	// extract PEM-encoded data block
	block, _ := pem.Decode(pemData)
	if block == nil {
		return nil, errors.New("Bad key data")
	}
	if block.Type != "PUBLIC KEY" {
		return nil, errors.New("Unknown key type")
	}
	// Decode the RSA public key
	key, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	pub, ok := key.(*ecdsa.PublicKey)
	if ok == false {
		return nil, errors.New("Not an ECDSA public key")
	}
	return pub, nil
}

// Load RSA public key
func LoadPubRSA(path string) (*rsa.PublicKey, error) {
	pemData, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, err
	}
	// extract PEM-encoded data block
	block, _ := pem.Decode(pemData)
	if block == nil {
		return nil, errors.New("Bad key data")
	}
	if block.Type != "PUBLIC KEY" {
		return nil, errors.New("Unknown key type")
	}
	// Decode the RSA public key
	key, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	pub, ok := key.(*rsa.PublicKey)
	if ok == false {
		return nil, errors.New("Not an RSA public key")
	}
	return pub, nil
}

// These two functions are created to support PGP style encryption
// Encrypt AES key to be sent to client using RSA. pub is client's (or us if we are the client) public key.
// You preferably should use SetKey() first before using this, because this function get the key to be encrypted from package's KEY variable
// For JS, see https://github.com/travist/jsencrypt (The lib is using PKCS1)
// Returns encrypted key
func ExchangeAESKeyRSAEncrypt(oaep bool, label []byte, hasher *hash.Hash, pub *rsa.PublicKey) ([]byte, error) {
	var encrypted []byte
	var err error
	if oaep {
		encrypted, err = rsa.EncryptOAEP(*hasher, rand.Reader, pub, KEY, label)
		if err != nil {
			return []byte{}, err
		}
	} else {
		encrypted, err = rsa.EncryptPKCS1v15(rand.Reader, pub, KEY)
		if err != nil {
			return []byte{}, err
		}
	}
	return encrypted, nil
}

// Decrypt AES key from server to be used using RSA, pk is client's (or us if we are the client) private key. (
// You should only do this once to exchange AES key.
// This automatically set KEY variable, after that you can use New()
func ExchangeAESKeyRSADecrypt(oaep bool, encrypted, label []byte, hasher *hash.Hash, pk *rsa.PrivateKey) error {
	if oaep {
		key, err := rsa.DecryptOAEP(*hasher, rand.Reader, pk, encrypted, label)
		if err != nil {
			return err
		}
		KEY = key
	} else {
		err := rsa.DecryptPKCS1v15SessionKey(rand.Reader, pk, encrypted, KEY)
		if err != nil {
			return err
		}
	}
	return nil
}

// These PGPStyle* functions purposefully created for secure messaging from Go server to JS clients PGP style
// But you should not ever consider using it, at least for now
// create a pair of bit RSA keypair in PEM format
// Returns client pk, server pk, client pub, and server pub
func PGPStyleCreateKeypairs(bit int) ([]byte, []byte, []byte, []byte, error) {
	c, err := rsa.GenerateKey(rand.Reader, bit)
	if err != nil {
		return []byte{}, []byte{}, []byte{}, []byte{}, err
	}
	s, err := rsa.GenerateKey(rand.Reader, bit)
	if err != nil {
		return []byte{}, []byte{}, []byte{}, []byte{}, err
	}
	dcpk := x509.MarshalPKCS1PrivateKey(c)
	dspk := x509.MarshalPKCS1PrivateKey(s)
	dcpub, err := x509.MarshalPKIXPublicKey(c.Public())
	if err != nil {
		return []byte{}, []byte{}, []byte{}, []byte{}, err
	}
	dspub, err := x509.MarshalPKIXPublicKey(s.Public())
	if err != nil {
		return []byte{}, []byte{}, []byte{}, []byte{}, err
	}
	cpkb := &pem.Block{"RSA PRIVATE KEY", nil, dcpk}
	spkb := &pem.Block{"RSA PRIVATE KEY", nil, dspk}
	cpubb := &pem.Block{"PUBLIC KEY", nil, dcpub}
	spubb := &pem.Block{"PUBLIC KEY", nil, dspub}
	cpk := pem.EncodeToMemory(cpkb)
	spk := pem.EncodeToMemory(spkb)
	cpub := pem.EncodeToMemory(cpubb)
	spub := pem.EncodeToMemory(spubb)
	return cpk, spk, cpub, spub, nil
}

// Load key in PEM format and return as *rsa.PrivateKey
func PGPStyleLoadPrivateKey(pemPk []byte) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode(pemPk)
	if block.Type != "RSA PRIVATE KEY" {
		return nil, errors.New("Unknown key type")
	}
	return x509.ParsePKCS1PrivateKey(block.Bytes)
}

// Load key in PEM format and return as *rsa.PublicKey
func PGPStyleLoadPublicKey(pemPub []byte) (*rsa.PublicKey, error) {
	block, _ := pem.Decode(pemPub)
	if block.Type != "PUBLIC KEY" {
		return nil, errors.New("Unknown key type")
	}
	pubKey, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	pub, ok := pubKey.(*rsa.PublicKey)
	if ok == false {
		return nil, errors.New("Not an RSA public key")
	}
	return pub, nil
}

// Returns encrypted message, hash, nonce, additionalData, and encrypted key
func PGPStyleEncrypt(data []byte, pub *rsa.PublicKey) ([]byte, []byte, []byte, []byte, []byte, error) {
	key := make([]byte, 32)
	_, err := rand.Read(key)
	if err != nil {
		return []byte{}, []byte{}, []byte{}, []byte{}, []byte{}, err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return []byte{}, []byte{}, []byte{}, []byte{}, []byte{}, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return []byte{}, []byte{}, []byte{}, []byte{}, []byte{}, err
	}
	nonce := make([]byte, gcm.NonceSize())
	_, err = rand.Read(nonce)
	if err != nil {
		return []byte{}, []byte{}, []byte{}, []byte{}, []byte{}, err
	}
	additionalData := make([]byte, 32)
	_, err = rand.Read(additionalData)
	if err != nil {
		return []byte{}, []byte{}, []byte{}, []byte{}, []byte{}, err
	}
	encrypted := gcm.Seal(nil, nonce, data, additionalData)
	h := sha256.Sum256(encrypted)
	encKey, err := rsa.EncryptPKCS1v15(rand.Reader, pub, key)
	if err != nil {
		return []byte{}, []byte{}, []byte{}, []byte{}, []byte{}, err
	}
	return encrypted, h[:], nonce, additionalData, encKey, nil
}

// Returns decrypted message
func PGPStyleDecrypt(encrypted, h, nonce, additionalData, ekey []byte, pk *rsa.PrivateKey) ([]byte, error) {
	rh := sha256.Sum256(encrypted)
	if subtle.ConstantTimeCompare(h, rh[:]) != 1 {
		return []byte{}, errors.New("Failed to verify hash")
	}
	key := make([]byte, 32)
	err := rsa.DecryptPKCS1v15SessionKey(rand.Reader, pk, ekey, key)
	if err != nil {
		return []byte{}, err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return []byte{}, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return []byte{}, err
	}
	return gcm.Open(nil, nonce, encrypted, additionalData)
}

// Encrypt data to be send using ECDSA-AES256GCM-AEAD
// For JS, see http://bitwiseshiftleft.github.io/sjcl/doc/symbols/sjcl.mode.gcm.html and https://github.com/cryptocoinjs/ecdsa just remember to use prime256v1 (secp256r1)
// Returns encrypted data, r, s, and nonce
func (b *ENC) EncryptECDSASend(data []byte, pk *ecdsa.PrivateKey) ([]byte, []byte, []byte, []byte , error) {
	// encrypt with AES256GCM-AEAD
	nonce := make([]byte, b.GCM.NonceSize())
	_, err := rand.Read(nonce)
	if err != nil {
		return []byte{}, []byte{}, []byte{}, []byte{}, err
	}
	encrypted := b.GCM.Seal(nil, nonce, data, DATA)
	// then create the signature
	r, s, err := ecdsa.Sign(rand.Reader, pk, encrypted)
	if err != nil {
		return []byte{}, []byte{}, []byte{}, []byte{}, err
	}
	return encrypted, r.Bytes(), s.Bytes(), nonce, nil
}

// Encrypt data to be send using RSA-AES256GCM-AEAD
// For JS, see http://bitwiseshiftleft.github.io/sjcl/doc/symbols/sjcl.mode.gcm.html and https://github.com/travist/jsencrypt
// Returns encrypted data, sign, and nonce
func (b *ENC) EncryptRSASend(data []byte, pk *rsa.PrivateKey) ([]byte, []byte, []byte, error) {
	// encrypt with AES256GCM-AEAD
	nonce := make([]byte, b.GCM.NonceSize())
	_, err := rand.Read(nonce)
	if err != nil {
		return []byte{}, []byte{}, []byte{}, err
	}
	encrypted := b.GCM.Seal(nil, nonce, data, DATA)
	// then create the signature
	s, err := rsa.SignPKCS1v15(rand.Reader, pk, 0, encrypted)
	if err != nil {
		return []byte{}, []byte{}, []byte{}, err
	}

	return encrypted, s, nonce, nil
}

// Decrypt the encrypted data
// Returns the decrypted data
func (b *ENC) DecryptECDSA(encrypted, rb, sb, nonce []byte, pub *ecdsa.PublicKey) ([]byte, error) {
	// turn rb and sb to *big.Int first
	r := new(big.Int)
	r.SetBytes(rb)
	s := new(big.Int)
	s.SetBytes(sb)
	// First we verify the content
	ok := ecdsa.Verify(pub, encrypted, r, s)
	if ok == false {
		return []byte{}, errors.New("Failed to verify content")
	}
	// then we open the msg
	msg, err := b.GCM.Open(nil, nonce, encrypted, DATA)
	if err != nil {
		return []byte{}, err
	}
	return msg, nil
}

// Decrypt the encrypted data
// Returns the decrypted data
func (b *ENC) DecryptRSA(encrypted, s, nonce []byte, pub *rsa.PublicKey) ([]byte, error) {
	// First we verify the content
	err := rsa.VerifyPKCS1v15(pub, 0, encrypted, s)
	if err != nil {
		return []byte{}, err
	}
	// then we open the msg
	msg, err := b.GCM.Open(nil, nonce, encrypted, DATA)
	if err != nil {
		return []byte{}, err
	}
	return msg, nil
}

// Encrypt data using scrypt -> ECDSA-AES256GCM-AEAD to be stored
// returns encrypted, r, s, and nonce. Preferably store them each in different databases (or machines) if you can
func (b *ENC) EncryptECDSAStore(data, salt []byte, pk *ecdsa.PrivateKey) ([]byte, []byte, []byte, []byte, error) {
	// First hash with scrypt
	data, err := scrypt.Key(data, salt, 1 << 14, 8, 1, 32)
	if err != nil {
		return []byte{}, []byte{}, []byte{}, []byte{}, err
	}
	// Next encrypt with AES256GCM
	nonce := make([]byte, b.GCM.NonceSize())
	_, err = rand.Read(nonce)
	if err != nil {
		return []byte{}, []byte{}, []byte{}, []byte{}, err
	}
	// nonce and DATA should not be different if we wish to open the content
	encrypted := b.GCM.Seal([]byte{}, nonce, data, DATA)

	// then create the signature
	r, s, err := ecdsa.Sign(rand.Reader, pk, encrypted)
	if err != nil {
		return []byte{}, []byte{}, []byte{}, []byte{}, err
	}

	return encrypted, r.Bytes(), s.Bytes(), nonce, nil
}

// Encrypt data using scrypt -> RSA-AES256GCM-AEAD to be stored
// returns encrypted, sign, and nonce. Preferably store them each in different databases (or machines) if you can
func (b *ENC) EncryptRSAStore(data, salt []byte, pk *rsa.PrivateKey) ([]byte, []byte, []byte, error) {
	// First hash with scrypt
	data, err := scrypt.Key(data, salt, 1 << 14, 8, 1, 32)
	if err != nil {
		return []byte{}, []byte{}, []byte{}, err
	}

	// Next encrypt with AES256GCM
	nonce := make([]byte, b.GCM.NonceSize())
	_, err = rand.Read(nonce)
	if err != nil {
		return []byte{}, []byte{}, []byte{}, err
	}
	// nonce and DATA should not be different if we wish to open the content
	encrypted := b.GCM.Seal(nil, nonce, data, DATA)

	// then create the signature
	s, err := rsa.SignPKCS1v15(rand.Reader, pk, 0, encrypted)
	if err != nil {
		return []byte{}, []byte{}, []byte{}, err
	}

	return encrypted, s, nonce, nil
}

// Validate data
func (b *ENC) ValidateECDSA(password, salt, encrypted, rb, sb, nonce []byte, pub *ecdsa.PublicKey) error {
	// Turn rb and sb into *big.Int first
	r := new(big.Int)
	r.SetBytes(rb)
	s := new(big.Int)
	s.SetBytes(sb)
	// First we verify the content
	ok := ecdsa.Verify(pub, encrypted, r, s)
	if ok == false {
		return errors.New("Failed to verify content")
	}

	// then we open the msg
	h, err := b.GCM.Open(nil, nonce, encrypted, DATA)
	if err != nil {
		return err
	}

	// then verify the hash with plaintext password
	data, err := scrypt.Key(password, salt, 1 << 14, 8, 1, 32)
	if err != nil {
		return err
	}
	if subtle.ConstantTimeCompare(h, data) != 1 {
		return errors.New("Failed to verify hash")
	}

	return nil
}

// Validate data
func (b *ENC) ValidateRSA(password, salt, encrypted, s, nonce []byte, pub *rsa.PublicKey) error {
	// First we verify the content
	err := rsa.VerifyPKCS1v15(pub, 0, encrypted, s)
	if err != nil {
		return err
	}

	// then we open the msg
	h, err := b.GCM.Open(nil, nonce, encrypted, DATA)
	if err != nil {
		return err
	}

	// then verify the hash with plaintext password
	data, err := scrypt.Key(password, salt, 1 << 14, 8, 1, 32)
	if err != nil {
		return err
	}
	if subtle.ConstantTimeCompare(h, data) != 1 {
		return errors.New("Failed to verify hash")
	}

	return nil
}

type NACL struct {
	Pub [32]byte
	Priv [32]byte
	SK [32]byte
}

// Create new NACL struct
func NewNACL() (*NACL, error) {
	pub, priv, err := box.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	return &NACL{*pub, *priv, [32]byte{}}, nil
}

// Returns 32 byte pub and 64 byte pk for EdDSA (Ed25519)
func GenEdDSAKeyPair() ([32]byte, [64]byte, error) {
	pub, pk, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return [32]byte{}, [64]byte{}, err
	}
	return *pub, *pk, err
}

// Encrypt data to be stored using NaCL-EdDSA, be sure to do SetKey() beforehand.
// Please don't forget to store the salt.
// Returns encrypted data, signature, and nonce.
func EncryptNACLStore(data, salt []byte, ecpk [64]byte) ([]byte, [64]byte, [24]byte, error) {
	var key [32]byte
	copy(key[:], KEY)
	non := make([]byte, 24)
	_, err := rand.Read(non)
	if err != nil {
		return []byte{}, [64]byte{}, [24]byte{}, err
	}
	var nonce [24]byte
	copy(nonce[:], non)
	data, err = scrypt.Key(data, salt, 1 << 14, 8, 1, 32)
	if err != nil {
		return []byte{}, [64]byte{}, [24]byte{}, err
	}
	data = secretbox.Seal([]byte{}, data, &nonce, &key)
	sign := ed25519.Sign(&ecpk, data)
	return data, *sign, nonce, nil
}

// Decrypt stored data using NaCL-EdDSA to be validated.
func ValidateNACL(password, salt, encrypted []byte, sign [64]byte, nonce [24]byte, pub [32]byte, key []byte) error {
	if ed25519.Verify(&pub, encrypted, &sign) == false {
		return errors.New("Failed to verify content")
	}
	var k [32]byte
	copy(k[:], key)
	h, ok := secretbox.Open([]byte{}, encrypted, &nonce, &k)
	if ok == false {
		return errors.New("Failed to decrypt content")
	}
	// then verify the hash with plaintext password
	data, err := scrypt.Key(password, salt, 1 << 14, 8, 1, 32)
	if err != nil {
		return err
	}
	if subtle.ConstantTimeCompare(h, data) != 1 {
		return errors.New("Failed to verify hash")
	}
	return nil
}

// Generate SK from other party's public key
func (n *NACL) GenSharedKey(ppub *[32]byte) {
	box.Precompute(&n.SK, ppub, &n.Priv)
}

// Encrypt the message, returns encrypted data, hash, and nonce
func (n *NACL) Encrypt(msg, salt []byte, ppub *[32]byte) ([]byte, []byte, [24]byte, error) {
	non := make([]byte, 24)
	_, err := rand.Read(non)
	if err != nil {
		return []byte{}, []byte{}, [24]byte{}, err
	}
	var nonce [24]byte
	copy(nonce[:], non)
	e := box.Seal([]byte{}, msg, &nonce, ppub, &n.Priv)
	x := append(salt[:16], e...)
	x = append(x, salt[16:]...)
	h := sha512.Sum512(x)
	return e, h[:], nonce, nil
}

// Decrypt the message, returns decrypted data
func (n *NACL) Decrypt(encrypted, h, salt []byte, nonce *[24]byte, ppub *[32]byte) ([]byte, bool) {
	x := append(salt[:16], encrypted...)
	x = append(x, salt[16:]...)
	rh := sha512.Sum512(x)
	if subtle.ConstantTimeCompare(h, rh[:]) != 1 {
		return []byte{}, false
	}
	d, ok := box.Open([]byte{}, encrypted, nonce, ppub, &n.Priv)
	if ok == false {
		return []byte{}, ok
	}
	return d, ok
}

// Encrypt the message using shared key, returns encrypted data, hash, and nonce
func (n *NACL) EncryptSK(msg, salt []byte) ([]byte, []byte, [24]byte, error) {
	non := make([]byte, 24)
	_, err := rand.Read(non)
	if err != nil {
		return []byte{}, []byte{}, [24]byte{}, err
	}
	var nonce [24]byte
	copy(nonce[:], non)
	e := box.SealAfterPrecomputation([]byte{}, msg, &nonce, &n.SK)
	x := append(e, salt...)
	h := sha512.Sum512(x)
	return e, h[:], nonce, nil
}

// Decrypt the message using shared key, returns decrypted data
func (n *NACL) DecryptSK(encrypted, h, salt []byte, nonce *[24]byte) ([]byte, bool) {
	x := append(encrypted, salt...)
	rh := sha512.Sum512(x)
	if subtle.ConstantTimeCompare(h, rh[:]) != 1 {
		return []byte{}, false
	}
	d, ok := box.OpenAfterPrecomputation([]byte{}, encrypted, nonce, &n.SK)
	if ok == false {
		return []byte{}, ok
	}
	return d, ok
}