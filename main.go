package main

import (
	cryptorand "crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"passwordmanager/models"

	"github.com/google/uuid"
	"github.com/joho/godotenv"
	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
	"golang.org/x/crypto/bcrypt"
)

var encryptionKey []byte

func init() {

	err := godotenv.Load(".env")
	if err != nil {
		panic("Error loading .evn file")
	}

	key := os.Getenv("ENCRYPTION_KEY")
	if key == "" {
		panic("ENCRYPTION_KEY is missing")
	}
	if len(key) != 32 {
		panic("ENCRYPTION_KEY must be 32 bytes long")
	}
	encryptionKey = []byte(key)
}

var users = map[string]models.User{}

var LoginAttempts = map[string]models.LoginAttempt{}

var tokens = map[string]models.TokenInfo{}

func getEncryptionKey() []byte {
	return encryptionKey
}

func generateAuthToken() string {
	b := make([]byte, 32)
	if _, err := cryptorand.Read(b); err != nil {
		panic("failed to generate token")
	}
	return hex.EncodeToString(b)
}

func generatePassword(length int) (string, error) { // @NOTE: func name has a typo
	const charset = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*()_+-"

	if len(charset) > 256 {
		return "", fmt.Errorf("charset too large")
	}

	randomBytes := make([]byte, length)

	if _, err := cryptorand.Read(randomBytes); err != nil {
		return "", err
	}

	result := make([]byte, length)
	charsetLen := len(charset)

	for i, randomByte := range randomBytes {
		index := int(randomByte) % charsetLen
		result[i] = charset[index]
	}

	return string(result), nil
}

func generateGroupID() string {
	return uuid.NewString()
}

func sendJSON(
	w http.ResponseWriter,
	status int,
	payload interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(payload)
}

func decodeJSONBody(
	r *http.Request,
	dst interface{}) error {
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	return decoder.Decode(dst)
}

func hasUppercase(s string) bool {
	for _, ch := range s {
		if ch >= 'A' && ch <= 'Z' {
			return true
		}
	}
	return false
}

func hasTooManyConsecutiveChars(s string) bool {
	count := 0
	for i := 1; i < len(s); i++ {
		if s[i] == s[i-1] {
			count++
			if count >= 3 {
				return true
			}
		} else {
			count = 0
		}
	}
	return false
}

func hasSymbol(s string) bool {
	symbols := "!@#$%^&*()-+"
	for _, c := range s {
		if strings.ContainsRune(symbols, c) {
			return true
		}
	}
	return false
}

func main() {

	e := echo.New()

	e.Use(middleware.Logger())
	e.Use(middleware.Recover())

	e.POST("/sign_up", SignUp)
	e.POST("/log_in", Login)
	e.POST("/add_password", AddPassword)
	e.GET("/list_passwords", ListPasswords)
	e.POST("/generate_password", GeneratePasswordHandler)

	e.Logger.Fatal(e.Start(":8080"))
}

func SignUp(c echo.Context) error {
	var body models.SignUpRequest

	if err := c.Bind(&body); err != nil {
		return c.JSON(400, models.ErrorResponse{Error: "Invalid input"})
	}

	username := strings.ToLower(strings.TrimSpace(body.Username))
	password := strings.TrimSpace(body.Password)

	if username == "" || password == "" {
		return c.JSON(400, models.ErrorResponse{Error: "Username and password required"})
	}

	if len(username) < 6 {
		return c.JSON(400, models.ErrorResponse{Error: "Username must be at least 6 characters long"})
	}

	if _, exists := users[username]; exists {
		return c.JSON(400, models.ErrorResponse{Error: "User already exists"})
	}

	if len(password) < 12 {
		return c.JSON(400, models.ErrorResponse{Error: "Password must be at least 12 characters long"})
	}

	if !hasUppercase(password) {
		return c.JSON(400, models.ErrorResponse{Error: "Password must contain at least one uppercase letter"})
	}

	if hasTooManyConsecutiveChars(password) {
		return c.JSON(400, models.ErrorResponse{Error: "Password cannot have more than 3 consecutive identical characters"})
	}

	if !hasSymbol(password) {
		return c.JSON(400, models.ErrorResponse{Error: "Password must contain a special character"})
	}

	if strings.Contains(strings.ToLower(password), strings.ToLower(username)) {
		return c.JSON(400, models.ErrorResponse{Error: "Password must not contain username"})
	}

	hashedPassword, err := bcrypt.GenerateFromPassword(
		[]byte(password),
		bcrypt.DefaultCost,
	)
	if err != nil {
		return c.JSON(500, models.ErrorResponse{Error: "Error hashing password"})
	}

	users[username] = models.User{
		Username:  username,
		Password:  string(hashedPassword),
		Passwords: []models.PasswordInfo{},
	}

	return c.JSON(201, models.MessageResponse{Message: "Registration successful"})
}

func Login(c echo.Context) error {

	var body models.LoginRequest

	if err := c.Bind(&body); err != nil {
		return c.JSON(400, models.ErrorResponse{Error: "invalid input"})
	}

	username := strings.ToLower(strings.TrimSpace(body.Username))
	password := strings.TrimSpace(body.Password)

	if username == "" || password == "" {
		return c.JSON(400, models.ErrorResponse{Error: "username and password required"})
	}

	attempt := LoginAttempts[username]

	if attempt.Count >= 5 {
		waitMinutes := 15 - int(time.Since(attempt.BlockedAt).Minutes())
		if waitMinutes > 0 {
			return c.JSON(429, models.ErrorResponse{Error: fmt.Sprintf("Too many failed login attempts. Please try again after %d minute(s)", waitMinutes)})
		}
		attempt = models.LoginAttempt{}
		LoginAttempts[username] = attempt
	}

	user, exists := users[username]
	if !exists {
		attempt.Count++
		if attempt.Count >= 5 {
			attempt.BlockedAt = time.Now()
		}
		LoginAttempts[username] = attempt
		return c.JSON(401, models.MessageResponse{Message: "Invalid Username or Password"})
	}

	if err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(password)); err != nil {
		attempt.Count++
		if attempt.Count >= 5 {
			attempt.BlockedAt = time.Now()
		}
		LoginAttempts[username] = attempt
		return c.JSON(http.StatusUnauthorized, models.MessageResponse{Message: "Invalid Username or Password"})
	}
	//what about this??//
	delete(LoginAttempts, username)

	token := generateAuthToken()
	expiry := time.Now().Add(24 * time.Hour)
	tokens[token] = models.TokenInfo{
		Username: username,
		Expiry:   expiry,
	}

	return c.JSON(200, models.LoginResponse{
		Token:  token,
		Expiry: expiry,
	})
}

func AddPassword(c echo.Context) error {

	var body models.AddPasswordRequest

	if err := c.Bind(&body); err != nil {
		return c.JSON(400, models.ErrorResponse{Error: "invalid input"})

	}

	if strings.TrimSpace(body.Name) == "" {
		return c.JSON(400, models.ErrorResponse{
			Error: "Name is required",
		})
	}

	token := c.Request().Header.Get("Authorization")
	tokenInfo, ok := ValidateToken(token)
	if !ok {
		return c.JSON(401, models.ErrorResponse{Error: "Invalid or expired token"})
	}

	username := tokenInfo.Username
	user, ok := users[username]
	if !ok {
		return c.JSON(400, models.ErrorResponse{Error: "User not found"})
	}

	password := body.Password

	if password == "" {
		var err error
		password, err = generatePassword(16)
		if err != nil {
			return c.JSON(400, models.ErrorResponse{Error: "Password generation failed"})
		}
	}

	key := getEncryptionKey()
	encryptedPassword, err := EncryptAES(password, key)
	if err != nil {
		return c.JSON(400, models.ErrorResponse{Error: "Encryption failed"})
	}

	pass := models.PasswordInfo{
		Name:     body.Name,
		Username: body.Username,
		Password: encryptedPassword,
	}

	user.Passwords = append(user.Passwords, pass)
	users[username] = user

	return c.JSON(200, models.MessageResponse{Message: "Password Saved"})
}

func ValidateToken(token string) (models.TokenInfo, bool) {
	t, ok := tokens[token]
	if !ok || time.Now().After(t.Expiry) {
		delete(tokens, token)
		return models.TokenInfo{}, false
	}
	return t, true
}

func ListPasswords(c echo.Context) error {

	token := c.Request().Header.Get("Authorization")
	tokenInfo, ok := ValidateToken(token)
	if !ok {
		return c.JSON(401, models.ErrorResponse{Error: "Invalid or expired token"})
	}

	user, exists := users[tokenInfo.Username]
	if !exists {
		return c.JSON(400, models.ErrorResponse{Error: "User not found"})
	}

	key := getEncryptionKey()

	passwords := make([]models.PasswordInfo, 0, len(user.Passwords))
	for _, pass := range user.Passwords {
		decrypted, err := DecryptAES(pass.Password, key)
		if err != nil {
			return c.JSON(500, models.ErrorResponse{Error: "Failed to decrypt passwords"})
		}
		passCopy := pass
		passCopy.Password = decrypted
		passwords = append(passwords, passCopy)
	}

	response := models.ListPasswordsResponse{
		Passwords: passwords,
		Count:     len(passwords),
	}

	return c.JSON(200, response)
}

func GeneratePasswordHandler(c echo.Context) error {
	length := 16

	pass, err := generatePassword(length)
	if err != nil {
		return c.JSON(500, models.ErrorResponse{
			Error: "Password generation failed",
		})
	}
	return c.JSON(200, map[string]string{
		"password": pass,
	})
}
