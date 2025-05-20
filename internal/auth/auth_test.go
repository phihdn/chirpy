package auth

import (
	"net/http"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

func TestHashPassword(t *testing.T) {
	password := "my-secure-password"

	// Test that hashing doesn't return an error
	hashedPassword, err := HashPassword(password)
	if err != nil {
		t.Errorf("HashPassword returned an error: %v", err)
	}

	// Test that the hashed password is not empty
	if hashedPassword == "" {
		t.Error("HashPassword returned an empty hash")
	}

	// Test that the hashed password is not the same as the original password
	if hashedPassword == password {
		t.Error("HashPassword did not hash the password")
	}
}

func TestCheckPasswordHash(t *testing.T) {
	password := "my-secure-password"
	wrongPassword := "wrong-password"

	// Hash the password
	hashedPassword, err := HashPassword(password)
	if err != nil {
		t.Fatalf("HashPassword returned an error: %v", err)
	}

	// Test that checking the same password succeeds
	err = CheckPasswordHash(hashedPassword, password)
	if err != nil {
		t.Errorf("CheckPasswordHash returned an error for the correct password: %v", err)
	}

	// Test that checking a wrong password fails
	err = CheckPasswordHash(hashedPassword, wrongPassword)
	if err == nil {
		t.Error("CheckPasswordHash did not return an error for the wrong password")
	}
}

func TestHashPassword_DifferentHashes(t *testing.T) {
	password := "my-secure-password"

	// Generate two hashes for the same password
	hash1, err := HashPassword(password)
	if err != nil {
		t.Fatalf("HashPassword returned an error: %v", err)
	}

	hash2, err := HashPassword(password)
	if err != nil {
		t.Fatalf("HashPassword returned an error: %v", err)
	}

	// Test that the hashes are different (bcrypt should include a random salt)
	if hash1 == hash2 {
		t.Error("HashPassword produced the same hash for the same password twice, which suggests the salt is not random")
	}

	// Test that both hashes validate against the original password
	if err = CheckPasswordHash(hash1, password); err != nil {
		t.Errorf("CheckPasswordHash failed for first hash: %v", err)
	}

	if err = CheckPasswordHash(hash2, password); err != nil {
		t.Errorf("CheckPasswordHash failed for second hash: %v", err)
	}
}

func TestMakeJWT(t *testing.T) {
	// Create a test user ID
	userID := uuid.New()
	tokenSecret := "test-secret"
	expiresIn := time.Hour * 24

	// Generate JWT
	token, err := MakeJWT(userID, tokenSecret, expiresIn)
	if err != nil {
		t.Fatalf("MakeJWT returned an error: %v", err)
	}

	// Validate token is not empty
	if token == "" {
		t.Error("MakeJWT returned an empty token")
	}

	// Parse and validate the token
	parsedToken, err := jwt.Parse(token, func(token *jwt.Token) (interface{}, error) {
		// Validate the algorithm is what we expect
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			t.Errorf("Unexpected signing method: %v", token.Header["alg"])
		}
		return []byte(tokenSecret), nil
	})
	if err != nil {
		t.Errorf("Failed to parse token: %v", err)
	}
	if !parsedToken.Valid {
		t.Error("Generated token is invalid")
	}

	// Verify claims
	if claims, ok := parsedToken.Claims.(jwt.MapClaims); ok {
		// Check subject equals user ID
		subject, err := claims.GetSubject()
		if err != nil {
			t.Errorf("Failed to get subject from token: %v", err)
		}
		if subject != userID.String() {
			t.Errorf("Token subject does not match user ID. Got %s, want %s", subject, userID.String())
		}

		// Check issuer is "chirpy"
		issuer, err := claims.GetIssuer()
		if err != nil {
			t.Errorf("Failed to get issuer from token: %v", err)
		}
		if issuer != "chirpy" {
			t.Errorf("Token issuer mismatch. Got %s, want %s", issuer, "chirpy")
		}

		// Check expiration time is correct (with some tolerance)
		expClaim, err := claims.GetExpirationTime()
		if err != nil {
			t.Errorf("Failed to get expiration time from token: %v", err)
		}
		expectedExpiration := time.Now().UTC().Add(expiresIn)
		tolerance := 5 * time.Second

		diff := expectedExpiration.Sub(expClaim.Time)
		if diff < -tolerance || diff > tolerance {
			t.Errorf("Token expiration time mismatch. Got %v, want close to %v", expClaim.Time, expectedExpiration)
		}
	} else {
		t.Error("Failed to parse token claims")
	}
}

func TestMakeJWT_DifferentSecrets(t *testing.T) {
	userID := uuid.New()
	secret1 := "secret-1"
	secret2 := "secret-2"
	expiresIn := time.Hour

	// Generate tokens with different secrets
	token1, _ := MakeJWT(userID, secret1, expiresIn)
	token2, _ := MakeJWT(userID, secret2, expiresIn)

	// Tokens should be different
	if token1 == token2 {
		t.Error("Tokens generated with different secrets should be different")
	}

	// Verify first token with wrong secret should fail
	_, err := jwt.Parse(token1, func(token *jwt.Token) (interface{}, error) {
		return []byte(secret2), nil
	})
	if err == nil {
		t.Error("Token verification should fail with incorrect secret")
	}
}

func TestValidateJWT_ValidToken(t *testing.T) {
	// Create a test user ID
	originalUserID := uuid.New()
	tokenSecret := "test-secret"
	expiresIn := time.Hour * 24

	// Generate JWT
	token, err := MakeJWT(originalUserID, tokenSecret, expiresIn)
	if err != nil {
		t.Fatalf("MakeJWT returned an error: %v", err)
	}

	// Validate the token
	userID, err := ValidateJWT(token, tokenSecret)
	if err != nil {
		t.Errorf("ValidateJWT returned an error for a valid token: %v", err)
	}

	// Check that the user ID matches
	if userID != originalUserID {
		t.Errorf("ValidateJWT returned wrong user ID. Got %v, want %v", userID, originalUserID)
	}
}

func TestValidateJWT_ExpiredToken(t *testing.T) {
	// Create a test user ID
	userID := uuid.New()
	tokenSecret := "test-secret"
	// Token that expired 1 hour ago
	expiresIn := -1 * time.Hour

	// Generate JWT (already expired)
	token, err := MakeJWT(userID, tokenSecret, expiresIn)
	if err != nil {
		t.Fatalf("MakeJWT returned an error: %v", err)
	}

	// Validate the token (should fail)
	_, err = ValidateJWT(token, tokenSecret)
	if err == nil {
		t.Error("ValidateJWT did not return an error for an expired token")
	}
}

func TestValidateJWT_WrongSecret(t *testing.T) {
	// Create a test user ID
	userID := uuid.New()
	tokenSecret := "correct-secret"
	wrongSecret := "wrong-secret"
	expiresIn := time.Hour * 24

	// Generate JWT
	token, err := MakeJWT(userID, tokenSecret, expiresIn)
	if err != nil {
		t.Fatalf("MakeJWT returned an error: %v", err)
	}

	// Validate with wrong secret
	_, err = ValidateJWT(token, wrongSecret)
	if err == nil {
		t.Error("ValidateJWT did not return an error when token was verified with wrong secret")
	}
}

func TestValidateJWT_MalformedToken(t *testing.T) {
	tokenSecret := "test-secret"
	malformedToken := "not.a.validtoken"

	// Validate malformed token
	_, err := ValidateJWT(malformedToken, tokenSecret)
	if err == nil {
		t.Error("ValidateJWT did not return an error for a malformed token")
	}
}

func TestValidateJWT_InvalidUserID(t *testing.T) {
	// Create a custom token with invalid subject claim
	claims := jwt.RegisteredClaims{
		Subject:   "not-a-valid-uuid",
		Issuer:    "chirpy",
		IssuedAt:  jwt.NewNumericDate(time.Now().UTC()),
		ExpiresAt: jwt.NewNumericDate(time.Now().UTC().Add(time.Hour)),
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenSecret := "test-secret"

	// Sign the token
	tokenString, err := token.SignedString([]byte(tokenSecret))
	if err != nil {
		t.Fatalf("Failed to sign test token: %v", err)
	}

	// Validate token with invalid UUID
	_, err = ValidateJWT(tokenString, tokenSecret)
	if err == nil {
		t.Error("ValidateJWT did not return an error for a token with an invalid user ID")
	}
}

func TestValidateJWT_EmptyUserID(t *testing.T) {
	// Create a custom token with empty subject claim
	claims := jwt.RegisteredClaims{
		Subject:   "",
		Issuer:    "chirpy",
		IssuedAt:  jwt.NewNumericDate(time.Now().UTC()),
		ExpiresAt: jwt.NewNumericDate(time.Now().UTC().Add(time.Hour)),
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenSecret := "test-secret"

	// Sign the token
	tokenString, err := token.SignedString([]byte(tokenSecret))
	if err != nil {
		t.Fatalf("Failed to sign test token: %v", err)
	}

	// Validate token with empty user ID
	_, err = ValidateJWT(tokenString, tokenSecret)
	if err == nil {
		t.Error("ValidateJWT did not return an error for a token with an empty user ID")
	}
}

func TestTokenRoundTrip(t *testing.T) {
	// Test full lifecycle - create, validate, check
	userID := uuid.New()
	tokenSecret := "my-super-secret-key"
	expiresIn := time.Hour

	// Create token
	token, err := MakeJWT(userID, tokenSecret, expiresIn)
	if err != nil {
		t.Fatalf("Failed to create token: %v", err)
	}

	// Validate token
	extractedID, err := ValidateJWT(token, tokenSecret)
	if err != nil {
		t.Fatalf("Failed to validate token: %v", err)
	}

	// Check that the extracted ID matches the original
	if extractedID != userID {
		t.Errorf("User ID mismatch after round trip. Got %v, want %v", extractedID, userID)
	}
}

func TestGetBearerToken(t *testing.T) {
	tests := []struct {
		name          string
		headers       http.Header
		expectedToken string
		expectError   bool
	}{
		{
			name: "Valid Authorization header",
			headers: http.Header{
				"Authorization": []string{"Bearer abc123.def456.ghi789"},
			},
			expectedToken: "abc123.def456.ghi789",
			expectError:   false,
		},
		{
			name: "Authorization header with extra spaces",
			headers: http.Header{
				"Authorization": []string{"Bearer   abc123.def456.ghi789  "},
			},
			expectedToken: "abc123.def456.ghi789",
			expectError:   false,
		},
		{
			name:        "No Authorization header",
			headers:     http.Header{},
			expectError: true,
		},
		{
			name: "Authorization header without Bearer",
			headers: http.Header{
				"Authorization": []string{"NotBearer abc123.def456.ghi789"},
			},
			expectError: true,
		},
		{
			name: "Empty token after Bearer",
			headers: http.Header{
				"Authorization": []string{"Bearer "},
			},
			expectError: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			token, err := GetBearerToken(tc.headers)

			// Check error expectation
			if tc.expectError && err == nil {
				t.Error("Expected an error but got none")
			}
			if !tc.expectError && err != nil {
				t.Errorf("Did not expect an error but got: %v", err)
			}

			// If we expect success, check the token value
			if !tc.expectError {
				if token != tc.expectedToken {
					t.Errorf("Token mismatch. Got %q, want %q", token, tc.expectedToken)
				}
			}
		})
	}
}
