package jwtool

import (
	"encoding/json"
	"fmt"

	"github.com/dgrijalva/jwt-go"
)

// Decode ...
func Decode(tokenString, key string) ([]byte, bool) {
	token, _ := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("Unexpected signing method: %v", token.Header["alg"])
		}
		return []byte(key), nil
	})
	if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
		data, _ := json.Marshal(claims)
		return data, true
	}
	return nil, false
}
