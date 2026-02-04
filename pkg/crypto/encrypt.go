package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
)

const NonceLength = 12 // GCM standard nonce size

// Encrypt encrypts plaintext using AES-256-GCM with the given key
// Returns: nonce (12 bytes) + ciphertext + tag (16 bytes)
func Encrypt(plaintext, key []byte) ([]byte, error) {
	if len(key) != KeyLength {
		return nil, errors.New("invalid key length: must be 32 bytes")
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, NonceLength)
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}

	// Seal appends ciphertext + tag to nonce
	ciphertext := gcm.Seal(nonce, nonce, plaintext, nil)
	return ciphertext, nil
}

// Decrypt decrypts ciphertext using AES-256-GCM with the given key
// Expects: nonce (12 bytes) + ciphertext + tag (16 bytes)
func Decrypt(ciphertext, key []byte) ([]byte, error) {
	if len(key) != KeyLength {
		return nil, errors.New("invalid key length: must be 32 bytes")
	}

	if len(ciphertext) < NonceLength {
		return nil, errors.New("ciphertext too short")
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonce := ciphertext[:NonceLength]
	ciphertextWithTag := ciphertext[NonceLength:]

	plaintext, err := gcm.Open(nil, nonce, ciphertextWithTag, nil)
	if err != nil {
		return nil, errors.New("decryption failed: invalid password or corrupted data")
	}

	return plaintext, nil
}
