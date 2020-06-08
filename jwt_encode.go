package jwtool

import "github.com/dgrijalva/jwt-go"

// Encode ...
func Encode() (string, error) {
	token := jwt.New(jwt.SigningMethodES512)
	if err != nil {
		return nil, err
	}
	claims := make(jwt.MapClaims)
	claims["a1"] = 111
	claims["a2"] = 222
	token.Claims = claims
	tokenString, err := token.SignedString([]byte("123456"))
	return tokenString, err
}
