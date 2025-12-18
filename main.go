package main

import (
	"encoding/json"
	"net/http"
	"strings"
)

func main() {

	http.HandleFunc("/signup", SignUp)
	http.HandleFunc("/login", Login)
	http.HandleFunc("/addpassword", AddPassword)
	http.ListenAndServe(":8080", nil)
}

var users = map[string]string{}
var userPasswords = map[string][]map[string]string{}
var AddPasswords = map[string][]map[string]string{}

func SignUp(
	w http.ResponseWriter,
	r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	var body map[string]string
	json.NewDecoder(r.Body).Decode(&body)

	username := strings.TrimSpace(body["username"])
	password := body["password"]

	if username == "" || password == "" {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte(`{"error":"invalid input"}`))
		return
	}

	if len(username) < 6 {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte(`{"error":"wrong uersname}`))
		return
	}
	if users[username] != "" {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte(`{"error":"User already exists"}`))
		return
	}

	if len(password) < 12 {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte(`{"error":"Weak password"}`))
		return
	}

	hasCaital := false
	for _, ch := range password {
		if ch >= 'A' && ch <= 'Z' {
			hasCaital = true
			break
		}
	}

	if !hasCaital {
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

	commonPasswords := []string{
		"password", "123456", "654321", "abc12345", "1q2w3e4r5t", "09876", "qwertyu",
	}
	for _, common := range commonPasswords {
		if password == common {
			w.WriteHeader(http.StatusBadRequest)
			w.Write([]byte(`{"error":"password is too common"}`))
			return
		}
	}

	users[username] = password
	userPasswords[username] = []map[string]string{}
	w.WriteHeader(http.StatusCreated)
	w.Write([]byte(`{"message":"Registration successful"}`))
}

func Login(
	w http.ResponseWriter,
	r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	var body map[string]string
	json.NewDecoder(r.Body).Decode(&body)

	username := body["username"]
	password := body["password"]

	storedPassword, ok := users[username]
	if !ok {
		w.WriteHeader(http.StatusNotFound)
		w.Write([]byte(`{"error":"User not found"}`))
		return
	}

	if storedPassword != password {
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte(`{"error":"Wrong Password"}`))
		return
	}

	w.WriteHeader(http.StatusOK)
	w.Write([]byte(`{"message":"Login Successful"}`))
}

func AddPassword(
	w http.ResponseWriter,
	r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	var body map[string]string
	json.NewDecoder(r.Body).Decode(&body)

	username := body["username"]

	if _, ok := users[username]; !ok {
		w.WriteHeader(http.StatusNotFound)
		w.Write([]byte(`{"error":"User not found"}`))
		return
	}

	pass := map[string]string{
		"name":     body["name"],
		"value":    body["password"],
		"platform": body["platform"],
	}

	userPasswords[username] = append(userPasswords[username], pass)
	w.Write([]byte(`{"message":"Password Saved"}`))
	//	fmt.Fprintln(w, "password saved")
}
