package auth

import (
	"golang.org/x/crypto/bcrypt"
)

// HashPassword hashes the password using bcrypt
func HashPassword(password string) (string, error) {
	// Generate the hashed password using bcrypt
	// The second parameter is the cost, which determines how much time
	// is needed to calculate a single bcrypt hash. The higher the cost,
	// the more secure but slower the function will be.
	hashedPasswordBytes, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return "", err
	}
	return string(hashedPasswordBytes), nil
}

// CheckPasswordHash compares the password with the hashed password
func CheckPasswordHash(hash, password string) error {
	// CompareHashAndPassword compares a bcrypt hashed password with its
	// possible plaintext equivalent. Returns nil on success, or an error on failure.
	return bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
}
