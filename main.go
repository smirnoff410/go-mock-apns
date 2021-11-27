package main

import (
  "fmt"
  "crypto/ecdsa"
	"io/ioutil"
	"strings"

	"github.com/golang-jwt/jwt/v4"
)

func main(){
  var err error

		key, _ := ioutil.ReadFile("/home/vladislav/.ssh/id_ecdsa.pub")

		var ecdsaKey *ecdsa.PublicKey
		if ecdsaKey, err = jwt.ParseECPublicKeyFromPEM(key); err != nil {
			fmt.Println("Unable to parse ECDSA public key: %v", err)
		}

		parts := strings.Split("eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NiJ9.eyJmb28iOiJiYXIifQ.feG39E-bn8HXAKhzDZq7yEAPWYDhZlwTn3sePJnU9VrGMmwdXAIEyoOnrjreYlVM_Z4N13eK9-TmMTWyfKJtHQ", ".")

		method := jwt.GetSigningMethod("ES256")
		err = method.Verify(strings.Join(parts[0:2], "."), parts[2], ecdsaKey)
		if err != nil {
			fmt.Println("[Basic ES256] Error while verifying key: %v", err)
		}
}
