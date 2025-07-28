package jwt

import (
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"github.com/golang-jwt/jwt/v5"
)

func validateToken(tokenString string, publicKey string) (*jwt.Token, error) {
	// валидируем токен проверяя корректность подписи
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		// реализуем функцию для получения публичного ключа
		block, _ := pem.Decode([]byte(publicKey))
		if block == nil {
			return nil, fmt.Errorf("failed to parse PEM block")
		}
		pubKey, err := x509.ParsePKCS1PublicKey(block.Bytes)
		if err != nil {
			return nil, err
		}
		return pubKey, nil
	})

	if err != nil {
		return nil, err
	}
	if !token.Valid {
		return nil, fmt.Errorf("invalid token")
	}
	return token, nil
}

func ParseToken(tokenString string, publicKey string) (int64, []string, error) {
	token, err := validateToken(tokenString, publicKey)
	if err != nil {
		return 0, []string{}, err
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return 0, []string{}, errors.New("invalid claims format")
	}

	// Получаем uid
	uid, ok := claims["uid"].(float64)
	if !ok {
		return 0, []string{}, errors.New("uid not found or invalid type")
	}

	// Получаем roles
	roles, ok := claims["roles"].([]string)
	if !ok {
		return 0, []string{}, errors.New("roleId not found or invalid type")
	}

	return int64(uid), roles, nil

}
