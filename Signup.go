package main

import (
	"fmt"
	"net/http"
)

var users = map[string]string{}
var savepasswords = map[string]string{}

func signup(
	w http.ResponseWriter,
	r *http.Request) {
	username := r.FormValue("username")
	password := r.FormValue("password")
	users[username] = password
	fmt.Fprintln(w, "Registration successful")

}

func login(
	w http.ResponseWriter,
	r *http.Request) {
	username := r.FormValue("username")
	password := r.FormValue("password")

	storedPassword, ok := users[username]
	if !ok {
		fmt.Fprintln(w, "User are not found")
		return
	}

	if storedPassword != password {
		fmt.Fprintln(w, "wrong password")
		return
	}

	fmt.Fprintln(w, "Login successful")
}

func addpassword(
	w http.ResponseWriter,
	r *http.Request) {
	username := r.FormValue("username")
	newpassword := r.FormValue("password")

	_, ok := users[username]
	if !ok {
		fmt.Fprintln(w, "User don't exist")
		return
	}

	savepasswords[username] = newpassword
	fmt.Fprintln(w, "password saved")

}

func main() {
	http.HandleFunc("/signup", signup)
	http.HandleFunc("/login", login)
	http.HandleFunc("/addpassword", addpassword)
	http.ListenAndServe(":8080", nil)

}
