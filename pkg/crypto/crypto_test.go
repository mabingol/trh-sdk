package crypto

import (
	"bytes"
	"testing"
)

// ============================================
// Argon2 Tests
// ============================================

func TestGenerateSalt(t *testing.T) {
	salt1, err := GenerateSalt()
	if err != nil {
		t.Fatalf("GenerateSalt failed: %v", err)
	}

	if len(salt1) != SaltLength {
		t.Errorf("Expected salt length %d, got %d", SaltLength, len(salt1))
	}

	// Ensure salts are random (not identical)
	salt2, _ := GenerateSalt()
	if bytes.Equal(salt1, salt2) {
		t.Error("Two generated salts should not be identical")
	}
}

func TestDeriveKey_Deterministic(t *testing.T) {
	password := []byte("test-password-123")
	salt := []byte("0123456789abcdef") // 16 bytes

	key1 := DeriveKey(password, salt)
	key2 := DeriveKey(password, salt)

	if !bytes.Equal(key1, key2) {
		t.Error("Same password and salt should produce same key")
	}

	if len(key1) != KeyLength {
		t.Errorf("Expected key length %d, got %d", KeyLength, len(key1))
	}
}

func TestDeriveKey_DifferentSalts(t *testing.T) {
	password := []byte("test-password-123")
	salt1 := []byte("0123456789abcdef")
	salt2 := []byte("fedcba9876543210")

	key1 := DeriveKey(password, salt1)
	key2 := DeriveKey(password, salt2)

	if bytes.Equal(key1, key2) {
		t.Error("Different salts should produce different keys")
	}
}

func TestDeriveKey_DifferentPasswords(t *testing.T) {
	salt := []byte("0123456789abcdef")
	password1 := []byte("password1")
	password2 := []byte("password2")

	key1 := DeriveKey(password1, salt)
	key2 := DeriveKey(password2, salt)

	if bytes.Equal(key1, key2) {
		t.Error("Different passwords should produce different keys")
	}
}

// ============================================
// Encrypt/Decrypt Tests
// ============================================

func TestEncryptDecrypt_RoundTrip(t *testing.T) {
	plaintext := []byte("Hello, this is secret data!")
	key := make([]byte, KeyLength)
	copy(key, "12345678901234567890123456789012")

	ciphertext, err := Encrypt(plaintext, key)
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}

	if bytes.Equal(plaintext, ciphertext) {
		t.Error("Ciphertext should not equal plaintext")
	}

	decrypted, err := Decrypt(ciphertext, key)
	if err != nil {
		t.Fatalf("Decrypt failed: %v", err)
	}

	if !bytes.Equal(plaintext, decrypted) {
		t.Error("Decrypted data should match original plaintext")
	}
}

func TestEncrypt_RandomNonce(t *testing.T) {
	plaintext := []byte("Same data")
	key := make([]byte, KeyLength)
	copy(key, "12345678901234567890123456789012")

	ciphertext1, _ := Encrypt(plaintext, key)
	ciphertext2, _ := Encrypt(plaintext, key)

	if bytes.Equal(ciphertext1, ciphertext2) {
		t.Error("Encrypting same data twice should produce different ciphertext (random nonce)")
	}
}

func TestDecrypt_WrongKey(t *testing.T) {
	plaintext := []byte("Secret!")
	key1 := make([]byte, KeyLength)
	key2 := make([]byte, KeyLength)
	copy(key1, "12345678901234567890123456789012")
	copy(key2, "abcdefghijklmnopqrstuvwxyz123456")

	ciphertext, _ := Encrypt(plaintext, key1)

	_, err := Decrypt(ciphertext, key2)
	if err == nil {
		t.Error("Decrypt with wrong key should fail")
	}
}

func TestDecrypt_TamperedCiphertext(t *testing.T) {
	plaintext := []byte("Secret!")
	key := make([]byte, KeyLength)
	copy(key, "12345678901234567890123456789012")

	ciphertext, _ := Encrypt(plaintext, key)

	// Tamper with ciphertext
	ciphertext[len(ciphertext)-1] ^= 0xFF

	_, err := Decrypt(ciphertext, key)
	if err == nil {
		t.Error("Decrypt of tampered ciphertext should fail")
	}
}

func TestEncrypt_InvalidKeyLength(t *testing.T) {
	plaintext := []byte("data")
	shortKey := []byte("short")

	_, err := Encrypt(plaintext, shortKey)
	if err == nil {
		t.Error("Encrypt with invalid key length should fail")
	}
}

func TestDecrypt_CiphertextTooShort(t *testing.T) {
	key := make([]byte, KeyLength)
	shortCiphertext := []byte("short")

	_, err := Decrypt(shortCiphertext, key)
	if err == nil {
		t.Error("Decrypt with too short ciphertext should fail")
	}
}

// ============================================
// Keystore Tests
// ============================================

func TestKeystore_RoundTrip(t *testing.T) {
	data := []byte(`{"admin_private_key": "abc123", "sequencer_private_key": "def456"}`)
	password := []byte("secure-password")

	ks, err := EncryptToKeystore(data, password)
	if err != nil {
		t.Fatalf("EncryptToKeystore failed: %v", err)
	}

	if ks.Version != KeystoreVersion {
		t.Errorf("Expected version %d, got %d", KeystoreVersion, ks.Version)
	}

	decrypted, err := DecryptKeystore(ks, password)
	if err != nil {
		t.Fatalf("DecryptKeystore failed: %v", err)
	}

	if !bytes.Equal(data, decrypted) {
		t.Error("Decrypted keystore should match original data")
	}
}

func TestKeystore_WrongPassword(t *testing.T) {
	data := []byte("secret data")
	password := []byte("correct-password")
	wrongPassword := []byte("wrong-password")

	ks, _ := EncryptToKeystore(data, password)

	_, err := DecryptKeystore(ks, wrongPassword)
	if err == nil {
		t.Error("DecryptKeystore with wrong password should fail")
	}
}

func TestKeystore_MarshalUnmarshal(t *testing.T) {
	data := []byte("test data")
	password := []byte("password")

	ks, _ := EncryptToKeystore(data, password)

	marshaled, err := ks.Marshal()
	if err != nil {
		t.Fatalf("Marshal failed: %v", err)
	}

	unmarshaled, err := UnmarshalKeystore(marshaled)
	if err != nil {
		t.Fatalf("UnmarshalKeystore failed: %v", err)
	}

	if unmarshaled.Version != ks.Version {
		t.Error("Version mismatch after marshal/unmarshal")
	}
	if unmarshaled.Salt != ks.Salt {
		t.Error("Salt mismatch after marshal/unmarshal")
	}
	if unmarshaled.Ciphertext != ks.Ciphertext {
		t.Error("Ciphertext mismatch after marshal/unmarshal")
	}
}

func TestIsEncryptedKeystore(t *testing.T) {
	// Encrypted keystore
	data := []byte("test")
	password := []byte("pass")
	ks, _ := EncryptToKeystore(data, password)
	marshaled, _ := ks.Marshal()

	if !IsEncryptedKeystore(marshaled) {
		t.Error("Should detect encrypted keystore")
	}

	// Plain JSON (not encrypted)
	plainJSON := []byte(`{"admin_private_key": "abc123"}`)
	if IsEncryptedKeystore(plainJSON) {
		t.Error("Should not detect plain JSON as encrypted keystore")
	}

	// Invalid JSON
	invalidJSON := []byte("not json at all")
	if IsEncryptedKeystore(invalidJSON) {
		t.Error("Should not detect invalid JSON as encrypted keystore")
	}
}

func TestKeystore_EmptyData(t *testing.T) {
	data := []byte{}
	password := []byte("password")

	ks, err := EncryptToKeystore(data, password)
	if err != nil {
		t.Fatalf("EncryptToKeystore should handle empty data: %v", err)
	}

	decrypted, err := DecryptKeystore(ks, password)
	if err != nil {
		t.Fatalf("DecryptKeystore should handle empty data: %v", err)
	}

	if len(decrypted) != 0 {
		t.Error("Decrypted empty data should be empty")
	}
}

func TestKeystore_LargeData(t *testing.T) {
	// 1 MB of data
	data := make([]byte, 1024*1024)
	for i := range data {
		data[i] = byte(i % 256)
	}
	password := []byte("password")

	ks, err := EncryptToKeystore(data, password)
	if err != nil {
		t.Fatalf("EncryptToKeystore should handle large data: %v", err)
	}

	decrypted, err := DecryptKeystore(ks, password)
	if err != nil {
		t.Fatalf("DecryptKeystore should handle large data: %v", err)
	}

	if !bytes.Equal(data, decrypted) {
		t.Error("Large data should decrypt correctly")
	}
}
