# 🔐Nurvex
A secure password manager built with Go and HTML. Store passwords safely and generate strong ones easily.

🚧 Under Active Development
This project is currently being developed and improved. More features, security updates, and a full web interface are planned.

## ✨ About
Nurvex is a simple and secure password manager designed to help manage and protect credentials. It includes features like strong password generation, shared password group, login protection, and a web interface.

## Features

### 👤 Authentication
- Signup with strong password validation
- Secure login using bcrypt hashing
- Token-based authentication
- Logout support
- login attempt limiting to protect againest brute force attacks

### 🔒 Password Management
- Add passwords manually or generate strong ones
- Passwords encrypted with AES-256-GCM
- view all saved passwords
- Get a password by name
- Search passwords
- Delete passwords

### 👥 Group & Sharing
- Create groups
- Add members to groups
- Share passwords safely with a group
- only group members can see shared passwords

## 🛡️ Security Highlights
- Passwords are never stored in plain text
- User passwords are hashed with bcrypt
- Stored  passwords are encrypted with AES-GCM
- New nonce is generated for every encryption
- Token expiration handling
- Input validation on all endpoints

## 🛠️ Build with
- Go (backend)
- net/http (API habdling)
- bcrypt (password hashing)
- crypto/aes & crypto/cipher (AES-GCM encryption)
- In-memory storage (temporary for development)
- HTML - (Frontend interface)

## 🧪 API Testing 
- Bruno (Testing AI endpoints)
- dotenv (managing environment variables)

## 🗺️ Roadmap
- Move from in memory storage to SQLite
- Add passkeys
- Build a full web interface (HTML) for easier use
