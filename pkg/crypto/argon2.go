package crypto

import (
	"crypto/rand"

	"golang.org/x/crypto/argon2"
)

// Argon2id parameters (OWASP recommended)
const (
	Memory      = 64 * 1024 // 64 MB
	Iterations  = 3
	Parallelism = 4
	KeyLength   = 32 // 256 bits for AES-256
	SaltLength  = 16
)

// DeriveKey derives a 256-bit key from password and salt using Argon2id
func DeriveKey(password, salt []byte) []byte {
	return argon2.IDKey(password, salt, Iterations, Memory, Parallelism, KeyLength)
}

// GenerateSalt generates a cryptographically secure random salt
func GenerateSalt() ([]byte, error) {
	salt := make([]byte, SaltLength)
	_, err := rand.Read(salt)
	if err != nil {
		return nil, err
	}
	return salt, nil
}
