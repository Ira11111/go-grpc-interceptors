package interceptors

import (
	"context"
	"github.com/Ira11111/go-grpc-interceptors/jwt"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"log"
	"strings"
)

const (
	register = "/auth.Auth/Register"
	login    = "/auth.Auth/Login"
)

type AuthInterceptor struct {
	key string
}

func NewAuthInterceptor(key string) *AuthInterceptor {
	return &AuthInterceptor{key: key}
}

func (a *AuthInterceptor) JWTClaims() grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error) {

		if info.FullMethod == register || info.FullMethod == login {
			log.Print("Public method")
			return handler(ctx, req)
		}

		md, ok := metadata.FromIncomingContext(ctx)
		if !ok {
			log.Print("No metadata")
			return nil, status.Errorf(codes.Unauthenticated, "missing metadata")
		}

		tokenStr := md["authorization"]
		if len(tokenStr) == 0 {
			log.Print("No token")
			return nil, status.Errorf(codes.Unauthenticated, "missing token")
		}
		token := strings.TrimPrefix(tokenStr[0], "Bearer ")

		userId, userRoles, err := jwt.ParseToken(token, a.key)
		if err != nil {
			log.Print("failed to parse token")
			switch err {
			case jwt.ErrInvalidPubKey:
				log.Print("Invalid key")
			case jwt.ErrInvalidClaims:
				log.Print("Invalid token claims")
			case jwt.ErrInvalidSignature:
				log.Print("Invalid token")
			case jwt.ErrInvalidToken:
				log.Print("Expired token")
			}
			return nil, status.Errorf(codes.Unauthenticated, "invalid token")
		}
		log.Printf("token parsed successfully")
		newCtx := context.WithValue(ctx, "userId", userId)
		newCtx = context.WithValue(newCtx, "userRoles", userRoles)
		log.Printf("context info added")
		return handler(ctx, req)
	}
}
