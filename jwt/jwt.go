package jwt

import (
	"crypto/x509"
	"encoding/pem"
	"errors"
	"github.com/golang-jwt/jwt/v5"
	"log"
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
			log.Printf("unexpected signing method: %v", token.Header["alg"])
			return nil, ErrInvalidSignature
		}

		block, _ := pem.Decode([]byte(publicKey))
		if block == nil {
			log.Printf("failed to decode PEM block")
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
		log.Println(err.Error())
		return nil, ErrInvalidSignature
	}
	if !token.Valid {
		log.Println("jwt invalid token")
		return nil, ErrInvalidToken
	}
	log.Println("jwt token valid")
	return token, nil
}

func ParseToken(tokenString string, publicKey string) (int64, []string, error) {
	token, err := validateToken(tokenString, publicKey)
	if err != nil {
		return 0, []string{}, err
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		log.Println("jwt claims invalid")
		return 0, []string{}, ErrInvalidClaims
	}

	// Получаем uid
	uid, ok := claims["uid"].(float64)
	if !ok {
		log.Println("jwt uid invalid")
		return 0, []string{}, ErrInvalidClaimsField
	}

	// Получаем roles
	roles, ok := claims["roles"].([]interface{})
	if !ok {
		log.Println("jwt roles invalid")
		return 0, []string{}, ErrInvalidClaimsField
	}

	res := make([]string, 0, len(roles))
	for _, role := range roles {
		r, ok := role.(string)
		if !ok {
			log.Println("jwt role is not a string")
			return 0, nil, ErrInvalidClaimsField
		}
		res = append(res, r)
	}

	log.Println("jwt claims valid")
	return int64(uid), res, nil

}
