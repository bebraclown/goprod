package main

import (
	"errors"
	"net/mail"
	"os"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/bcrypt"
)

const maxPasswordBytes = 72

var jwtSecret []byte

func InitAuth() error {
	secret := os.Getenv("JWT_SECRET")
	if len(strings.TrimSpace(secret)) < 32 {
		return errors.New("JWT_SECRET must contain at least 32 bytes")
	}
	jwtSecret = []byte(secret)
	return nil
}

func HashPassword(password string) (string, error) {
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	return string(hash), err
}

func CheckPassword(password, hash string) bool {
	return len(password) <= maxPasswordBytes &&
		bcrypt.CompareHashAndPassword([]byte(hash), []byte(password)) == nil
}

func GenerateToken(user User) (string, error) {
	now := time.Now()
	claims := Claims{
		UserID:   user.ID,
		Email:    user.Email,
		Username: user.Username,
		RegisteredClaims: jwt.RegisteredClaims{
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(24 * time.Hour)),
		},
	}
	return jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString(jwtSecret)
}

func ValidateToken(tokenString string) (*Claims, error) {
	claims := &Claims{}
	token, err := jwt.ParseWithClaims(tokenString, claims, func(_ *jwt.Token) (interface{}, error) {
		return jwtSecret, nil
	}, jwt.WithValidMethods([]string{jwt.SigningMethodHS256.Alg()}), jwt.WithExpirationRequired(), jwt.WithIssuedAt())
	if err != nil {
		return nil, err
	}
	if !token.Valid || claims.UserID <= 0 {
		return nil, errors.New("invalid token claims")
	}
	return claims, nil
}

func ValidatePassword(password string) error {
	if utf8.RuneCountInString(password) < 8 {
		return errors.New("password must be at least 8 characters long")
	}
	if len(password) > maxPasswordBytes {
		return errors.New("password must be at most 72 bytes long")
	}
	return nil
}

func ValidateEmail(email string) error {
	if email == "" {
		return errors.New("email is required")
	}
	address, err := mail.ParseAddress(email)
	if err != nil || address.Address != email || len(email) > 255 {
		return errors.New("invalid email address")
	}
	return nil
}
