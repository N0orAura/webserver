package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/joho/godotenv"
	"golang.org/x/crypto/bcrypt"
)

func EncryptAES(plainText string, key []byte) (string, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}

	cipherText := gcm.Seal(nonce, nonce, []byte(plainText), nil)
	return base64.StdEncoding.EncodeToString(cipherText), nil
}

func DecryptAES(cipherText string, key []byte) (string, error) {
	data, err := base64.StdEncoding.DecodeString(cipherText)
	if err != nil {
		return "", err
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	nonceSize := gcm.NonceSize()
	nonce, cipherData := data[:nonceSize], data[nonceSize:]

	plainText, err := gcm.Open(nil, nonce, cipherData, nil)
	if err != nil {
		return "", err
	}

	return string(plainText), nil
}

func loadEncryptionKey() []byte {
	key := os.Getenv("ENCRYPTION_KEY")

	if key == "" {
		panic("ENCRYPTION_KEY is missing")
	}

	if len(key) != 32 {
		panic("ENCRYPTION_KEY must be 32 bytes long")
	}
	return []byte(key)
}

func main() {

	err := godotenv.Load(".env")
	if err != nil {
		panic("Error loading .env file")
	}

	http.HandleFunc("/sign_up", SignUp)
	http.HandleFunc("/log_in", Login)
	http.HandleFunc("/log_out", Logout)
	http.HandleFunc("/add_password", AddPassword)
	http.HandleFunc("/list_passwords", ListPasswords)
	http.HandleFunc("/get_password", GetPassword)
	http.HandleFunc("/search_passwords", SearchPasswords)
	http.HandleFunc("/delete_password", DeletePassword)
	http.ListenAndServe(":8080", nil)
}

type ErrorResponse struct {
	Error string `json:"error"`
}

type MessageResponse struct {
	Message string `json:"message"`
}

type PasswordInfo struct {
	Name     string `json:"name"`
	Username string `json:"username"`
	Password string `json:"password"`
}
type User struct {
	Username  string
	Password  string
	Passwords []PasswordInfo
}

var users = map[string]User{}

type TokenInfo struct {
	Username string
	Expiry   time.Time
}

var tokens = map[string]TokenInfo{}

type SignUpRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type LoginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type AddPasswordRequest struct {
	Name     string `json:"name"`
	Username string `json:"username"`
	Password string `json:"password"`
}

type StoredPassword struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

func generateToken() string {
	b := make([]byte, 32)
	rand.Read(b)
	return hex.EncodeToString(b)
}

func generatPassword(length int) (string, error) {
	const charset = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*()_+-"
	b := make([]byte, length)
	_, err := rand.Read(b)
	if err != nil {
		return "", err
	}

	for i := 0; i < length; i++ {
		b[i] = charset[int(b[i])%len(charset)]
	}

	return string(b), nil
}

func SignUp(
	w http.ResponseWriter,
	r *http.Request,
) {
	w.Header().Set("Content-Type", "application/json")

	var body SignUpRequest

	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(ErrorResponse{
			Error: "invalid input",
		})
		return
	}
	username := body.Username
	password := body.Password

	if username == "" || password == "" {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(ErrorResponse{
			Error: "invalid input",
		})
		return
	}

	if len(username) < 6 {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(ErrorResponse{
			Error: "username must be at least 6 characters long",
		})
		return
	}

	if _, exists := users[username]; exists {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(ErrorResponse{
			Error: "User already exists",
		})
		return
	}

	if len(password) < 12 {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(ErrorResponse{
			Error: "password must be at least 12 characters long",
		})
		return
	}

	hasCapital := false
	for _, ch := range password {
		if ch >= 'A' && ch <= 'Z' {
			hasCapital = true
			break
		}
	}

	if !hasCapital {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(ErrorResponse{
			Error: "must contain capital letter",
		})
		return
	}
	sameCount := 0
	for i := 1; i < len(password); i++ {
		if password[i] == password[i-1] {
			sameCount++
			if sameCount >= 3 {
				w.WriteHeader(http.StatusBadRequest)
				json.NewEncoder(w).Encode(ErrorResponse{
					Error: "cannot have more than 3 consecutive identical characters",
				})
				return
			}
		} else {
			sameCount = 0
		}
	}

	symbols := "!@#$%^&*()-+"
	hasSymbol := false
	for _, c := range password {
		if strings.ContainsRune(symbols, c) {
			hasSymbol = true
			break
		}
	}

	if !hasSymbol {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(ErrorResponse{
			Error: "must contain special character",
		})
		return
	}

	if strings.Contains(strings.ToLower(password), strings.ToLower(username)) {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(ErrorResponse{
			Error: "password must not contain username",
		})
		return
	}

	hashedPassword, err := bcrypt.GenerateFromPassword(
		[]byte(password),
		bcrypt.DefaultCost,
	)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(ErrorResponse{
			Error: "Error hashing password",
		})
		return
	}

	users[username] = User{
		Username:  username,
		Password:  string(hashedPassword),
		Passwords: []PasswordInfo{},
	}

	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(MessageResponse{
		Message: "Registration successful",
	})
}

func Login(
	w http.ResponseWriter,
	r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	var body LoginRequest

	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(ErrorResponse{
			Error: "invalid input",
		})
		return
	}

	username := body.Username
	password := body.Password

	user, ok := users[username]
	if !ok {
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(MessageResponse{
			Message: "Invalid Username or Password",
		})
		return
	}

	err := bcrypt.CompareHashAndPassword(
		[]byte(user.Password),
		[]byte(password),
	)
	if err != nil {
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(MessageResponse{
			Message: "Invalid Username or Password",
		})
		return
	}

	token := generateToken()
	tokens[token] = TokenInfo{
		Username: username,
		Expiry:   time.Now().Add(24 * time.Hour),
	}
	w.WriteHeader(http.StatusOK)

	json.NewEncoder(w).Encode(map[string]string{
		"token": token,
	})
}

func Logout(
	w http.ResponseWriter,
	r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	token := r.Header.Get("Authorization")
	delete(tokens, token)

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(MessageResponse{
		Message: "Logged out successfully",
	})
}

func AddPassword(
	w http.ResponseWriter,
	r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	var body AddPasswordRequest
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(ErrorResponse{
			Error: "invalid input",
		})
		return
	}

	token := r.Header.Get("Authorization")
	TokenInfo, ok := tokens[token]
	if !ok || time.Now().After(TokenInfo.Expiry) {
		delete(tokens, token)
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(ErrorResponse{
			Error: "Invalid or expired token",
		})
		return
	}
	username := TokenInfo.Username
	user, ok := users[username]
	if !ok {
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(ErrorResponse{
			Error: "User not found",
		})
		return
	}

	password := body.Password

	if password == "" {
		var err error
		password, err = generatPassword(16)
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(ErrorResponse{
				Error: "Password generation failed",
			})
			return
		}
	}

	if len(password) < 12 {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(ErrorResponse{
			Error: "password must be at least 12 characters long",
		})
		return
	}

	hasCapital := false
	for _, ch := range password {
		if ch >= 'A' && ch <= 'Z' {
			hasCapital = true
			break
		}
	}

	if !hasCapital {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(ErrorResponse{
			Error: "must contain capital letter",
		})
		return
	}

	sameCount := 0
	for i := 1; i < len(password); i++ {
		if password[i] == password[i-1] {
			sameCount++
			if sameCount >= 3 {
				w.WriteHeader(http.StatusBadRequest)
				json.NewEncoder(w).Encode(ErrorResponse{
					Error: "cannot have more than 3 consecutive identical characters",
				})
				return
			}
		} else {
			sameCount = 0
		}
	}

	symbols := "!@#$%^&*()-+"
	hasSymbol := false
	for _, c := range password {
		if strings.ContainsRune(symbols, c) {
			hasSymbol = true
			break
		}
	}

	if !hasSymbol {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(ErrorResponse{
			Error: "must contain special character",
		})
		return
	}

	if strings.Contains(strings.ToLower(password), strings.ToLower(username)) {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(ErrorResponse{
			Error: "password must not contain username",
		})
		return
	}

	key := loadEncryptionKey()
	encryptedPassword, err := EncryptAES(password, key)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(ErrorResponse{
			Error: "Encryption failed",
		})
		return
	}

	pass := PasswordInfo{
		Name:     body.Name,
		Username: body.Username,
		Password: encryptedPassword,
	}

	found := false
	for i, p := range user.Passwords {
		if p.Name == body.Name {
			user.Passwords[i] = pass
			found = true
			break
		}
	}

	if !found {
		user.Passwords = append(user.Passwords, pass)
	}

	users[username] = user
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(MessageResponse{
		Message: "Password Saved",
	})
}

func ListPasswords(
	w http.ResponseWriter,
	r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	token := r.Header.Get("Authorization")
	TokenInfo, ok := tokens[token]
	if !ok || time.Now().After(TokenInfo.Expiry) {
		delete(tokens, token)
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(ErrorResponse{
			Error: "Invalid or expired token",
		})
		return

	}

	username := TokenInfo.Username
	user := users[username]

	passwords := user.Passwords
	var response []PasswordInfo

	for _, pass := range passwords {
		passCopy := pass
		key := loadEncryptionKey()
		decrypted, err := DecryptAES(pass.Password, key)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		passCopy.Password = decrypted
		response = append(response, passCopy)
	}

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(user.Passwords)
}

func GetPassword(
	w http.ResponseWriter,
	r *http.Request) {

	token := r.Header.Get("Authorization")
	TokenInfo, ok := tokens[token]
	if !ok || time.Now().After(TokenInfo.Expiry) {
		delete(tokens, token)
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(ErrorResponse{
			Error: "Invalid or expired token",
		})
		return
	}

	name := r.URL.Query().Get("name")
	if name == "" {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(ErrorResponse{
			Error: "Password name is required",
		})
		return
	}

	user := users[TokenInfo.Username]
	for _, pass := range user.Passwords {
		if pass.Name == name {
			passCopy := pass
			key := loadEncryptionKey()
			decrypted, err := DecryptAES(pass.Password, key)
			if err != nil {
				w.WriteHeader(http.StatusInternalServerError)
				return
			}
			passCopy.Password = decrypted
			w.WriteHeader(http.StatusOK)
			json.NewEncoder(w).Encode(passCopy)
			return
		}
	}

	w.WriteHeader(http.StatusNotFound)
	json.NewEncoder(w).Encode(ErrorResponse{
		Error: "Password not found",
	})
}

func SearchPasswords(
	w http.ResponseWriter,
	r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	token := r.Header.Get("Authorization")
	TokenInfo, ok := tokens[token]
	if !ok || time.Now().After(TokenInfo.Expiry) {
		delete(tokens, token)
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(ErrorResponse{
			Error: "Invalid or expired token",
		})
		return
	}

	query := r.URL.Query().Get("query")
	if query == "" {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(ErrorResponse{
			Error: "Search query is required",
		})
		return
	}

	user := users[TokenInfo.Username]
	var results []PasswordInfo
	for _, pass := range user.Passwords {
		if strings.Contains(pass.Name, query) {
			passCopy := pass
			key := loadEncryptionKey()
			decrypted, err := DecryptAES(pass.Password, key)
			if err != nil {
				w.WriteHeader(http.StatusInternalServerError)
				return
			}
			passCopy.Password = decrypted
			results = append(results, passCopy)
		}
	}

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(results)
}

func DeletePassword(
	w http.ResponseWriter,
	r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	token := r.Header.Get("Authorization")
	TokenInfo, ok := tokens[token]
	if !ok || time.Now().After(TokenInfo.Expiry) {
		delete(tokens, token)
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(ErrorResponse{
			Error: "Invalid or expired token",
		})
		return
	}

	name := r.URL.Query().Get("name")
	if name == "" {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(ErrorResponse{
			Error: "Password name is required",
		})
		return
	}

	username := TokenInfo.Username
	user := users[username]

	for i, pass := range user.Passwords {
		if pass.Name == name {
			user.Passwords = append(
				user.Passwords[:i],
				user.Passwords[i+1:]...,
			)
			users[username] = user
			w.WriteHeader(http.StatusOK)
			json.NewEncoder(w).Encode(MessageResponse{
				Message: "Password deleted",
			})
			return
		}
	}

	w.WriteHeader(http.StatusNotFound)
	json.NewEncoder(w).Encode(ErrorResponse{
		Error: "Password not found",
	})
}
