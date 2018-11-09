// Responsible to  parse JWT token and validate token signing
// https://jwt.io/
package jwt

import (
	"crypto/rsa"
	"errors"
	"fmt"
	"os"
	"strings"

	jwtgo "github.com/dgrijalva/jwt-go"
)

func cleanToken(tokenRaw string) string {
	replaceOnce := 1
	return strings.Replace(tokenRaw, "Bearer ", "", replaceOnce)
}

func Parse(tokenRaw string, publicKey *rsa.PublicKey) (map[string]interface{}, error) {
	tokenCleaned := cleanToken(tokenRaw)
	tokenParsed, err := jwtgo.Parse(tokenCleaned, func(token *jwtgo.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwtgo.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("Unexpected signing method: %v", token.Header["alg"])
		}
		return publicKey, nil
	})
	if err != nil {
		return nil, err
	}

	if claims, ok := tokenParsed.Claims.(jwtgo.MapClaims); ok && tokenParsed.Valid {
		return claims, nil
	}
	return nil, fmt.Errorf("JWT has no valid token claims")
}

func IsJWTToken(token string) bool {
	return strings.HasPrefix(token, "Bearer")
}

func GetClientID(token map[string]interface{}) (string, error) {
	clientIDMapKey := "sub"
	if clientID, ok := token[clientIDMapKey]; ok {
		return clientID.(string), nil
	}
	return "", errors.New("JWT token without claim 'sub'")
}
