package grpc

import (
	"github.com/Ira11111/go-interceptors/jwt"
	"github.com/gin-gonic/gin"
	"log"
	"net/http"
	"strings"
)

const (
	BearerAuthScopes = "bearerAuth.Scopes"
)

type AuthMiddleware struct {
	key string
}

func NewAuthMiddleware(key string) *AuthMiddleware {
	return &AuthMiddleware{key: key}
}

func (a *AuthMiddleware) JWTClaims() gin.HandlerFunc {
	return func(c *gin.Context) {
		if _, exists := c.Get(BearerAuthScopes); exists {
			tokenStr := c.GetHeader("Authorization")
			if tokenStr == "" {
				log.Print("token empty")
				c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "token empty"})
				return
			}
			tokenParts := strings.Split(tokenStr, " ")
			if len(tokenParts) != 2 || tokenParts[0] != "Bearer" {
				log.Print("token format is invalid")
				c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "invalid token format"})
				return
			}
			token := tokenParts[1]
			userId, userRoles, err := jwt.ParseToken(token, a.key)
			if err != nil {
				log.Print("failed to parse token")
				switch err {
				case jwt.ErrInvalidPubKey:
					log.Print("Invalid key")
				case jwt.ErrInvalidSignature:
					log.Print("Invalid token signature")
				case jwt.ErrInvalidClaims:
					log.Print("Invalid token claims")
					c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "invalid token claims"})
					return
				case jwt.ErrInvalidToken:
					log.Print("Expired token")
					c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "expired token"})
					return
				case jwt.ErrInvalidClaimsField:
					log.Print("Invalid token field")
					c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "invalid token field"})
					return
				}
				c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "invalid token"})
				return
			}
			log.Printf("token parsed successfully")
			c.Set("userId", userId)
			c.Set("userRoles", userRoles)
			log.Printf("context info added")
			c.Next()
		}

	}
}
