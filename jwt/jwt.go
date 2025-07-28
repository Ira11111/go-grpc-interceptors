package jwt

import (
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"github.com/golang-jwt/jwt/v5"
)

var (
	ErrInvalidSignature   = errors.New("invalid signature")
	ErrInvalidPubKey      = errors.New("invalid public key")
	ErrInvalidToken       = errors.New("invalid token")
	ErrInvalidClaims      = errors.New("invalid claims")
	ErrInvalidClaimsField = errors.New("invalid claims field")
)

func validateToken(tokenString string, publicKey string) (*jwt.Token, error) {
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}

		block, _ := pem.Decode([]byte(publicKey))
		if block == nil {
			return nil, ErrInvalidPubKey
		}

		// Пробуем разные форматы ключей
		pubKey, err := x509.ParsePKCS1PublicKey(block.Bytes)
		if err != nil {
			pubKey2, err := x509.ParsePKIXPublicKey(block.Bytes)
			if err != nil {
				return nil, ErrInvalidPubKey
			}
			return pubKey2, nil
		}
		return pubKey, nil // <- Возвращаем только ключ, без ошибки
	})

	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidSignature, err)
	}
	if !token.Valid {
		return nil, ErrInvalidToken
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
		return 0, []string{}, ErrInvalidClaims
	}

	// Получаем uid
	uid, ok := claims["uid"].(float64)
	if !ok {
		return 0, []string{}, ErrInvalidClaimsField
	}

	// Получаем roles
	roles, ok := claims["roles"].([]string)
	if !ok {
		return 0, []string{}, ErrInvalidClaimsField
	}

	return int64(uid), roles, nil

}
