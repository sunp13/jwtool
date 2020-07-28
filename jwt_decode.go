package jwtool

import (
	"encoding/json"
	"fmt"
	"strconv"
	"time"

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

// Check ... 检查一下是否过期
func Check(tokenString, key, exp string) ([]byte, error) {
	token, _ := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("Unexpected signing method: %v", token.Header["alg"])
		}
		return []byte(key), nil
	})
	if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
		// 判断一下claims 是否过期
		unixI64, _ := strconv.ParseInt(fmt.Sprintf("%v", claims[exp]), 10, 64)
		if time.Unix(unixI64, 0).After(time.Now()) {
			// 过期返回错误
			return nil, fmt.Errorf("Token Expired")
		}
		data, _ := json.Marshal(claims)
		return data, nil
	}
	return nil, fmt.Errorf("Token Valid Failed")
}
