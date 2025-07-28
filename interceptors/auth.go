package interceptors

import (
	"context"
	"github.com/Ira11111/go-grpc-interceptors/jwt"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"strings"
)

type AuthInterceptor struct {
	key string
}

func NewAuthInterceptor(key string) *AuthInterceptor {
	return &AuthInterceptor{key: key}
}

func (a *AuthInterceptor) JWTIClaimsInterceptor(ctx context.Context, req interface{}, info grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error) {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return nil, status.Errorf(codes.Unauthenticated, "missing metadata")
	}

	tokenStr := md["authorization"]
	if len(tokenStr) == 0 {
		return nil, status.Errorf(codes.Unauthenticated, "missing token")
	}
	token := strings.TrimPrefix(tokenStr[0], "Bearer ")

	userId, userRoles, err := jwt.ParseToken(token, a.key)
	if err != nil {
		return nil, status.Errorf(codes.Unauthenticated, "invalid token")
	}
	newCtx := context.WithValue(ctx, "userId", userId)
	newCtx = context.WithValue(newCtx, "userRoles", userRoles)

	return handler(ctx, req)
}
