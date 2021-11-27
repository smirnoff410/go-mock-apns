package main

import (
  "fmt"
  "crypto/ecdsa"
	"io/ioutil"
	"strings"

	"github.com/golang-jwt/jwt/v4"
)

func main(){
  validPublicKey()

  validPrivateKey()
}

func validPublicKey(){
  var err error

	key, _ := ioutil.ReadFile("keys/ec256-public.pem")

	var ecdsaPublicKey *ecdsa.PublicKey
	if ecdsaPublicKey, err = jwt.ParseECPublicKeyFromPEM(key); err != nil {
		fmt.Println("Unable to parse ECDSA public key: %v", err)
	}

	parts := strings.Split("eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NiJ9.eyJmb28iOiJiYXIifQ.feG39E-bn8HXAKhzDZq7yEAPWYDhZlwTn3sePJnU9VrGMmwdXAIEyoOnrjreYlVM_Z4N13eK9-TmMTWyfKJtHQ", ".")

	method := jwt.GetSigningMethod("ES256")
	err = method.Verify(strings.Join(parts[0:2], "."), parts[2], ecdsaPublicKey)
	if err != nil {
		fmt.Println("[Basic ES256] Error while verifying key: %v", err)
	}
  fmt.Println("Success public key")
}

func validPrivateKey(){
  var err error

  key, _ := ioutil.ReadFile("keys/ec256-private.pem")

	var ecdsaPrivateKey *ecdsa.PrivateKey
	if ecdsaPrivateKey, err = jwt.ParseECPrivateKeyFromPEM(key); err != nil {
		fmt.Println("Unable to parse ECDSA private key: %v", err)
	}

  parts := strings.Split("eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NiJ9.eyJmb28iOiJiYXIifQ.feG39E-bn8HXAKhzDZq7yEAPWYDhZlwTn3sePJnU9VrGMmwdXAIEyoOnrjreYlVM_Z4N13eK9-TmMTWyfKJtHQ", ".")
  method := jwt.GetSigningMethod("ES256")
	toSign := strings.Join(parts[0:2], ".")
	sig, err := method.Sign(toSign, ecdsaPrivateKey)

	if err != nil {
		fmt.Println("[Basic ES256] Error signing token: %v", err)
	}
	if sig == parts[2] {
		fmt.Println("[Basic ES256] Identical signatures\nbefore:\n%v\nafter:\n%v", parts[2], sig)
	}

	err = method.Verify(toSign, sig, ecdsaPrivateKey.Public())
	if err != nil {
		fmt.Println("[Basic ES256] Sign produced an invalid signature: %v", err)
	}
  fmt.Println("Success private key")
}
