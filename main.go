package main

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"strings"

	"golang.org/x/crypto/bcrypt"
)

func main() {

	http.HandleFunc("/sign_up", SignUp)
	http.HandleFunc("/log_in", Login)
	http.HandleFunc("/add_password", AddPassword)
	http.ListenAndServe(":8080", nil)
}

type MessageResponse struct {
	Message string `json:"message"`
}

type PasswordInfo struct {
	Name     string `json:"name"`
	Value    string `json:"value"`
	Platform string `json:"platform"`
}
type User struct {
	Username  string
	Password  string
	Passwords []PasswordInfo
}

var users = map[string]User{}
var tokens = map[string]string{}

// var userPasswords = map[string][]map[string]string{}
//var AddPasswords = map[string][]map[string]string{}

type SignUpRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type LoginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type AddPasswordRequest struct {
	Username string `json:"username"`
	Name     string `json:"name"`
	Password string `json:"password"`
	Platform string `json:"platform"`
}

func generateToken() string {
	b := make([]byte, 32)
	rand.Read(b)
	return hex.EncodeToString(b)
}

func SignUp(
	w http.ResponseWriter,
	r *http.Request,
) {
	w.Header().Set("Content-Type", "application/json")

	var body SignUpRequest

	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte(`{"error":"invalid input"}`))
		return
	}
	username := body.Username
	password := body.Password

	if username == "" || password == "" {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte(`{"error":"invalid input"}`))
		return
	}

	if len(username) < 6 {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte(`{"error":"username must be at least 6 characters long"}`))
		return
	}

	if _, exists := users[username]; exists {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte(`{"error":"User already exists"}`))
		return
	}

	//	if users[username] != "" {
	//		w.WriteHeader(http.StatusBadRequest)
	//		w.Write([]byte(`{"error":"User already exists"}`))
	//		return
	//	}

	if len(password) < 12 {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte(`{"error":"password must be at least 12 characters long"}`))
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
		w.Write([]byte(`{"error":"must contain capital letter"}`))
		return
	}
	sameCount := 1
	for i := 1; i < len(password); i++ {
		if password[i] == password[i-1] {
			sameCount++
			if sameCount >= 4 {
				w.WriteHeader(http.StatusBadRequest)
				w.Write([]byte(`{"error":"cannot have more than 3 consecutive identical characters"}`))
				return
			}
		} else {
			sameCount = 1
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
		w.Write([]byte(`{"error":"must contain special character"}`))
		return
	}

	if strings.Contains(strings.ToLower(password), strings.ToLower(username)) {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte(`{"error":"password must not contain username"}`))
		return
	}

	hashedPassword, err := bcrypt.GenerateFromPassword(
		[]byte(password),
		bcrypt.DefaultCost,
	)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(`{"error":"Error hashing password"}`))
		return
	}

	//	commonPasswords := []string{
	//		"password1234", "123456789!@#", "#@!987654321", "abc123456789", "1q2w3e4r5t6y",
	//	}

	//	for _, common := range commonPasswords {
	//		if password == common {
	//			w.WriteHeader(http.StatusBadRequest)
	//			w.Write([]byte(`{"error":"password is too common"}`))
	//			return
	//		}
	//	}

	//	users[username] = password
	//	userPasswords[username] = []map[string]string{}
	//	w.WriteHeader(http.StatusCreated)
	//	w.Write([]byte(`{"message":"Registration successful"}`))
	//}

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

//comment//

func Login(
	w http.ResponseWriter,
	r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	var body LoginRequest

	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte(`{"error":"invalid input"}`))
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

	//	storedPassword, ok := users[username]
	//	if !ok {
	//		w.WriteHeader(http.StatusNotFound)
	//		w.Write([]byte(`{"error":"User not found"}`))
	//		return
	//	}

	//	if storedPassword != password {
	//		w.WriteHeader(http.StatusUnauthorized)
	//		w.Write([]byte(`{"error":"Wrong Password"}`))
	//		return
	//	}
	//	json.NewEncoder(w).Encode(MessageResponse{
	//		Message: "Login successful",
	//	})
	token := generateToken()
	tokens[token] = username
	w.WriteHeader(http.StatusOK)

	json.NewEncoder(w).Encode(map[string]string{
		"token": token,
	})
}

func AddPassword(
	w http.ResponseWriter,
	r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	var body AddPasswordRequest
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte(`{"error":"invalid input"}`))
		return
	}

	token := r.Header.Get("Authorization")
	username, ok := tokens[token]
	if !ok {
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte(`{"error":"Invalid token"}`))
		return
	}

	//username := body.Username

	user, ok := users[username]
	if !ok {
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte(`{"error":"User not found"}`))
		return
	}

	hashedValue, err := bcrypt.GenerateFromPassword(
		[]byte(body.Password),
		bcrypt.DefaultCost,
	)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(`{"error":"Error hashing password"}`))
		return
	}

	pass := PasswordInfo{
		Name:     body.Name,
		Value:    string(hashedValue),
		Platform: body.Platform,
	}

	user.Passwords = append(user.Passwords, pass)
	users[username] = user
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(`{"message":"Password Saved"}`))
}

//	if _, ok := users[username]; !ok {
//		w.WriteHeader(http.StatusNotFound)
//		w.Write([]byte(`{"error":"User not found"}`))
//		return
//	}

//	pass := map[string]string{
//		"name":     body.Name,
//		"value":    body.Password,
//		"platform": body.Platform,
//	}

//	userPasswords[username] = append(userPasswords[username], pass)
//	w.Write([]byte(`{"message":"Password Saved"}`))
//}
