package jwtool

import (
	"time"

	"github.com/dgrijalva/jwt-go"
)

// Encode ...
func Encode(data map[string]interface{}, expireTime time.Duration, key string) (string, error) {
	// 默认使用hs512摘要算法
	token := jwt.New(jwt.SigningMethodHS512)
	claims := make(jwt.MapClaims)
	// 内容
	for k, v := range data {
		claims[k] = v
	}
	// 超时时间
	claims["exp"] = time.Now().Add(expireTime).Unix()
	token.Claims = claims
	// 计算验签
	tokenString, err := token.SignedString([]byte(key))
	return tokenString, err
}
