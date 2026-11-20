package main

import (
	"database/sql"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net/http"
	"regexp"
	"strings"
)

var usernamePattern = regexp.MustCompile(`^[\p{L}\p{N}_-]{3,30}$`)

func RegisterHandler(w http.ResponseWriter, r *http.Request) {
	if !requireMethod(w, r, http.MethodPost) {
		return
	}

	var request RegisterRequest
	if err := parseJSONRequest(w, r, &request); err != nil {
		sendErrorResponse(w, "Invalid request body", http.StatusBadRequest)
		return
	}
	if err := validateRegisterRequest(&request); err != nil {
		sendErrorResponse(w, err.Error(), http.StatusBadRequest)
		return
	}

	exists, err := UserExistsByEmail(request.Email)
	if err != nil {
		sendInternalError(w, err)
		return
	}
	if exists {
		sendErrorResponse(w, errUserExists.Error(), http.StatusConflict)
		return
	}

	hash, err := HashPassword(request.Password)
	if err != nil {
		sendInternalError(w, err)
		return
	}
	user, err := CreateUser(request.Email, request.Username, hash)
	if errors.Is(err, errUserExists) {
		sendErrorResponse(w, errUserExists.Error(), http.StatusConflict)
		return
	}
	if err != nil {
		sendInternalError(w, err)
		return
	}
	sendAuthResponse(w, user, http.StatusCreated)
}

func LoginHandler(w http.ResponseWriter, r *http.Request) {
	if !requireMethod(w, r, http.MethodPost) {
		return
	}

	var request LoginRequest
	if err := parseJSONRequest(w, r, &request); err != nil {
		sendErrorResponse(w, "Invalid request body", http.StatusBadRequest)
		return
	}
	if err := validateLoginRequest(&request); err != nil {
		sendErrorResponse(w, err.Error(), http.StatusBadRequest)
		return
	}

	const invalidCredentials = "Invalid email or password"
	user, err := GetUserByEmail(request.Email)
	if errors.Is(err, sql.ErrNoRows) {
		sendErrorResponse(w, invalidCredentials, http.StatusUnauthorized)
		return
	}
	if err != nil {
		sendInternalError(w, err)
		return
	}
	if !CheckPassword(request.Password, user.PasswordHash) {
		sendErrorResponse(w, invalidCredentials, http.StatusUnauthorized)
		return
	}
	sendAuthResponse(w, user, http.StatusOK)
}

func ProfileHandler(w http.ResponseWriter, r *http.Request) {
	if !requireMethod(w, r, http.MethodGet) {
		return
	}

	userID, ok := GetUserIDFromContext(r)
	if !ok {
		rejectToken(w)
		return
	}
	user, err := GetUserByID(userID)
	if errors.Is(err, sql.ErrNoRows) {
		sendErrorResponse(w, "User not found", http.StatusNotFound)
		return
	}
	if err != nil {
		sendInternalError(w, err)
		return
	}
	sendJSONResponse(w, user, http.StatusOK)
}

func HealthHandler(w http.ResponseWriter, r *http.Request) {
	if !requireMethod(w, r, http.MethodGet) {
		return
	}
	if db == nil || db.PingContext(r.Context()) != nil {
		sendErrorResponse(w, "Database connection failed", http.StatusServiceUnavailable)
		return
	}
	sendJSONResponse(w, map[string]string{
		"status":  "ok",
		"message": "Service is running",
	}, http.StatusOK)
}

func requireMethod(w http.ResponseWriter, r *http.Request, method string) bool {
	if r.Method == method {
		return true
	}
	w.Header().Set("Allow", method)
	sendErrorResponse(w, "Method not allowed", http.StatusMethodNotAllowed)
	return false
}

func sendAuthResponse(w http.ResponseWriter, user *User, statusCode int) {
	token, err := GenerateToken(*user)
	if err != nil {
		sendInternalError(w, err)
		return
	}
	sendJSONResponse(w, AuthResponse{Token: token, User: *user}, statusCode)
}

func sendInternalError(w http.ResponseWriter, err error) {
	log.Printf("Request failed: %v", err)
	sendErrorResponse(w, "Internal server error", http.StatusInternalServerError)
}

func sendJSONResponse(w http.ResponseWriter, data interface{}, statusCode int) {
	body, err := json.Marshal(data)
	if err != nil {
		log.Printf("Error encoding JSON response: %v", err)
		body = []byte(`{"error":"Internal server error"}`)
		statusCode = http.StatusInternalServerError
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	if _, err := w.Write(body); err != nil {
		log.Printf("Error writing JSON response: %v", err)
	}
}

func sendErrorResponse(w http.ResponseWriter, message string, statusCode int) {
	sendJSONResponse(w, map[string]string{"error": message}, statusCode)
}

func parseJSONRequest(w http.ResponseWriter, r *http.Request, data interface{}) error {
	if r.Body == nil {
		return errors.New("request body is empty")
	}
	body := http.MaxBytesReader(w, r.Body, 8*1024)
	defer body.Close()

	decoder := json.NewDecoder(body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(data); err != nil {
		return err
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		return errors.New("request body must contain one JSON object")
	}
	return nil
}

func validateRegisterRequest(request *RegisterRequest) error {
	request.Email = strings.ToLower(strings.TrimSpace(request.Email))
	request.Username = strings.TrimSpace(request.Username)
	if err := ValidateEmail(request.Email); err != nil {
		return err
	}
	if !usernamePattern.MatchString(request.Username) {
		return errors.New("username must contain 3 to 30 letters, digits, underscores or hyphens")
	}
	return ValidatePassword(request.Password)
}

func validateLoginRequest(request *LoginRequest) error {
	request.Email = strings.ToLower(strings.TrimSpace(request.Email))
	if request.Email == "" {
		return errors.New("email is required")
	}
	if request.Password == "" {
		return errors.New("password is required")
	}
	return nil
}
