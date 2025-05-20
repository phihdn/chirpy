package auth

import (
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
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

// MakeJWT creates a JWT token for the given user ID with expiration
func MakeJWT(userID uuid.UUID, tokenSecret string, expiresIn time.Duration) (string, error) {
	// Create claims with user ID, issuer, and expiration time
	claims := jwt.RegisteredClaims{
		Subject:   userID.String(),
		Issuer:    "chirpy",
		IssuedAt:  jwt.NewNumericDate(time.Now().UTC()),
		ExpiresAt: jwt.NewNumericDate(time.Now().UTC().Add(expiresIn)),
	}

	// Create a new token with the claims
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	// Sign the token with the secret
	signedToken, err := token.SignedString([]byte(tokenSecret))
	if err != nil {
		return "", err
	}

	return signedToken, nil
}

// ValidateJWT validates a JWT token and returns the user ID
func ValidateJWT(tokenString, tokenSecret string) (uuid.UUID, error) {
	// Parse and validate the JWT token
	token, err := jwt.ParseWithClaims(tokenString, &jwt.RegisteredClaims{}, func(token *jwt.Token) (interface{}, error) {
		// Validate that the signing method is HMAC
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, errors.New("unexpected signing method in token")
		}
		return []byte(tokenSecret), nil
	})

	if err != nil {
		return uuid.Nil, err
	}

	if !token.Valid {
		return uuid.Nil, errors.New("token is invalid")
	}

	// Extract the claims
	claims, ok := token.Claims.(*jwt.RegisteredClaims)
	if !ok {
		return uuid.Nil, errors.New("error extracting claims from token")
	}

	// Get user ID from the subject claim
	subject := claims.Subject
	if subject == "" {
		return uuid.Nil, errors.New("token missing subject claim")
	}

	// Parse the UUID from the subject
	userID, err := uuid.Parse(subject)
	if err != nil {
		return uuid.Nil, errors.New("invalid user ID format in token")
	}

	return userID, nil
}

// GetBearerToken extracts the token from the Authorization header
func GetBearerToken(headers http.Header) (string, error) {
	authHeader := headers.Get("Authorization")
	if authHeader == "" {
		return "", errors.New("no Authorization header found")
	}

	// Check if it starts with "Bearer "
	if !strings.HasPrefix(authHeader, "Bearer ") {
		return "", errors.New("Authorization header must start with 'Bearer'")
	}

	// Extract the token part (everything after "Bearer ")
	token := strings.TrimPrefix(authHeader, "Bearer ")
	token = strings.TrimSpace(token)

	if token == "" {
		return "", errors.New("token not found in Authorization header")
	}

	return token, nil
}
