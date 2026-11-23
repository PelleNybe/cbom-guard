package main

import (
	"crypto/des"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/md5"
	"crypto/rand"
	"crypto/rsa"
)

func VulnerableGoCrypto() {
	// Comment: rsa.GenerateKey(rand.Reader, 2048) should not trigger
	_, _ = rsa.GenerateKey(rand.Reader, 2048)
	_, _ = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	_ = md5.New()
	_, _ = des.NewTripleDESCipher([]byte("123456789012345678901234"))
}
