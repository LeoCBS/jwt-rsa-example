// +build unit

package jwt_test

import (
	"crypto/rsa"
	"io/ioutil"
	"os"
	"testing"

	"github.com/LeoCBS/jwt-rsa-example/jwt"
	jwtgo "github.com/dgrijalva/jwt-go"
)

type user struct {
	Name string `json:"name"`
	Sub  string `json:"sub"`
	jwtgo.StandardClaims
}

type fixture struct {
	publicKey       *rsa.PublicKey
	publicKeyString string
	wrongPublicKey  *rsa.PublicKey
	privateKey      *rsa.PrivateKey
}

func setUp(t *testing.T) fixture {
	privateKeyBytes, _ := ioutil.ReadFile("resource/sample")
	privateKey, err := jwtgo.ParseRSAPrivateKeyFromPEM(privateKeyBytes)
	test.AssertNoError(t, err)
	publicKeyBytes, err := ioutil.ReadFile("resource/sample.pub")
	publicKey, err := jwtgo.ParseRSAPublicKeyFromPEM(publicKeyBytes)
	test.AssertNoError(t, err)
	wrongPublicKeyBytes, err := ioutil.ReadFile("resource/wrong_sample.pub")
	wrongPublicKey, err := jwtgo.ParseRSAPublicKeyFromPEM(wrongPublicKeyBytes)
	test.AssertNoError(t, err)
	return fixture{
		publicKey:       publicKey,
		wrongPublicKey:  wrongPublicKey,
		privateKey:      privateKey,
		publicKeyString: string(publicKeyBytes[:]),
	}
}

func createTokenString(t *testing.T, privateKey *rsa.PrivateKey, u *user) string {
	token := jwtgo.NewWithClaims(jwtgo.GetSigningMethod("RS256"), u)
	tokenstring, err := token.SignedString(privateKey)
	if err != nil {
		test.AssertNoError(t, err)
	}
	return tokenstring
}

func TestParseJWTTokenSuccess(t *testing.T) {
	f := setUp(t)
	u := &user{
		Name: "coxinha",
	}
	tokenString := createTokenString(t, f.privateKey, u)
	tokenParsed, err := jwt.Parse(tokenString, f.publicKey)
	test.AssertNoError(t, err)
	test.AssertEqual(t, u.Name, tokenParsed["name"])
}

func TestParseJWTTokenValidatePublicKey(t *testing.T) {
	f := setUp(t)
	u := &user{
		Name: "coxinha",
	}
	tokenString := createTokenString(t, f.privateKey, u)
	_, err := jwt.Parse(tokenString, f.wrongPublicKey)
	expectedErrorMsg := "crypto/rsa: verification error"
	test.AssertErrorAndErrorMessage(t, err, expectedErrorMsg)
}

func TestIsJWTToken(t *testing.T) {
	tokenExample := "Bearer whatever"
	isJWTToken := jwt.IsJWTToken(tokenExample)
	test.AssertTrue(t, isJWTToken, "is jwt token return false on valid token")
}

func TestIsntJWTToken(t *testing.T) {
	tokenExample := "isnt Bearer whatever"
	isJWTToken := jwt.IsJWTToken(tokenExample)
	test.AssertFalse(t, isJWTToken, "is jwt token return true on invalid token")
}

func TestGetClientIDOnError(t *testing.T) {
	jwtWrong := map[string]interface{}{"kmlo": "wrong"}
	_, err := jwt.GetClientID(jwtWrong)
	test.AssertError(t, err)
}

func TestGetClientIDSuccess(t *testing.T) {
	expectedID := "1BAYHSZLIFRybNHu1ZSX7PIJeHC"
	jwtToken := map[string]interface{}{"sub": expectedID}
	clientID, err := jwt.GetClientID(jwtToken)
	test.AssertNoError(t, err)
	test.AssertEqual(t, clientID, expectedID)
}
