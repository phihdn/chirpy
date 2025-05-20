package auth

import (
	"testing"
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
