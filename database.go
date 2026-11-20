package main

import (
	"database/sql"
	"errors"
	"fmt"
	"net"
	"net/url"

	"github.com/lib/pq"
)

var (
	db            *sql.DB
	errUserExists = errors.New("email or username already in use")
)

func InitDB() error {
	connectionURL := url.URL{
		Scheme: "postgres",
		User:   url.UserPassword(getEnv("DB_USER", "postgres"), getEnv("DB_PASSWORD", "postgres")),
		Host:   net.JoinHostPort(getEnv("DB_HOST", "localhost"), getEnv("DB_PORT", "5432")),
		Path:   "/" + getEnv("DB_NAME", "secure_service"),
	}
	options := connectionURL.Query()
	options.Set("sslmode", "disable")
	options.Set("connect_timeout", "5")
	connectionURL.RawQuery = options.Encode()

	connection, err := sql.Open("postgres", connectionURL.String())
	if err != nil {
		return fmt.Errorf("open database: %w", err)
	}
	if err := connection.Ping(); err != nil {
		connection.Close()
		return fmt.Errorf("ping database: %w", err)
	}
	db = connection
	return nil
}

func CloseDB() {
	if db != nil {
		db.Close()
	}
}

func CreateUser(email, username, passwordHash string) (*User, error) {
	const query = "INSERT INTO users (email, username, password_hash) VALUES ($1, $2, $3) RETURNING id, created_at"
	user := &User{Email: email, Username: username, PasswordHash: passwordHash}
	if err := db.QueryRow(query, email, username, passwordHash).Scan(&user.ID, &user.CreatedAt); err != nil {
		var pgError *pq.Error
		if errors.As(err, &pgError) && pgError.Code == "23505" {
			return nil, errUserExists
		}
		return nil, fmt.Errorf("create user: %w", err)
	}
	return user, nil
}

func GetUserByEmail(email string) (*User, error) {
	const query = "SELECT id, email, username, password_hash, created_at FROM users WHERE email = $1"
	user := &User{}
	err := db.QueryRow(query, email).Scan(&user.ID, &user.Email, &user.Username, &user.PasswordHash, &user.CreatedAt)
	if err != nil {
		return nil, fmt.Errorf("find user by email: %w", err)
	}
	return user, nil
}

func GetUserByID(userID int) (*User, error) {
	const query = "SELECT id, email, username, created_at FROM users WHERE id = $1"
	user := &User{}
	if err := db.QueryRow(query, userID).Scan(&user.ID, &user.Email, &user.Username, &user.CreatedAt); err != nil {
		return nil, fmt.Errorf("find user by ID: %w", err)
	}
	return user, nil
}

func UserExistsByEmail(email string) (bool, error) {
	const query = "SELECT EXISTS (SELECT 1 FROM users WHERE email = $1)"
	var exists bool
	if err := db.QueryRow(query, email).Scan(&exists); err != nil {
		return false, fmt.Errorf("check email: %w", err)
	}
	return exists, nil
}

func GetDB() *sql.DB {
	return db
}
