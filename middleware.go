package main

import (
	"context"
	"net/http"
	"strings"
)

type userIDContextKey struct{}

func AuthMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		parts := strings.Fields(r.Header.Get("Authorization"))
		if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") {
			rejectToken(w)
			return
		}
		claims, err := ValidateToken(parts[1])
		if err != nil {
			rejectToken(w)
			return
		}

		ctx := context.WithValue(r.Context(), userIDContextKey{}, claims.UserID)
		next(w, r.WithContext(ctx))
	}
}

func GetUserIDFromContext(r *http.Request) (int, bool) {
	userID, ok := r.Context().Value(userIDContextKey{}).(int)
	return userID, ok
}

func rejectToken(w http.ResponseWriter) {
	w.Header().Set("WWW-Authenticate", "Bearer")
	sendErrorResponse(w, "Invalid or missing token", http.StatusUnauthorized)
}
