package models

import (
	"time"
)

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
	ID        string
	Username  string
	Password  string
	Passwords []PasswordInfo
}

type TokenInfo struct {
	Username string
	Expiry   time.Time
}

type LoginAttempt struct {
	Count     int
	BlockedAt time.Time
}

type LoginResponse struct {
	Token  string    `json:"token"`
	Expiry time.Time `json:"expiry"`
}

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

type ListPasswordsResponse struct {
	Passwords []PasswordInfo `json:"passwords"`
	Count     int            `json:"count"`
}

type CreateGroupRequest struct {
	Name    string   `json:"name"`
	Members []string `json:"members"`
}

type Group struct {
	ID      string   `json:"id"`
	Name    string   `json:"name"`
	Owner   string   `json:"owner"`
	Members []string `json:"members"`
}

type SharedPassword struct {
	Name     string   `json:"name"`
	Password string   `json:"password"`
	Owner    string   `json:"owner"`
	GroupID  string   `json:"group_id"`
	Members  []string `json:"members"`
}

type SharePasswordRequest struct {
	GroupID  string `json:"group_id"`
	Name     string `json:"name"`
	Username string `json:"username"`
	Password string `json:"password"`
}
