package crypto

import (
	"encoding/base64"
	"encoding/json"
	"errors"
)

// KeystoreVersion is the current keystore format version
const KeystoreVersion = 1

// EncryptedKeystore represents the encrypted settings file format
type EncryptedKeystore struct {
	Version    int    `json:"version"`
	Salt       string `json:"salt"`       // Base64-encoded
	Ciphertext string `json:"ciphertext"` // Base64-encoded (nonce + ciphertext + tag)
}

// EncryptToKeystore encrypts data with password and returns a keystore
func EncryptToKeystore(data, password []byte) (*EncryptedKeystore, error) {
	salt, err := GenerateSalt()
	if err != nil {
		return nil, err
	}

	key := DeriveKey(password, salt)
	ciphertext, err := Encrypt(data, key)
	if err != nil {
		return nil, err
	}

	return &EncryptedKeystore{
		Version:    KeystoreVersion,
		Salt:       base64.StdEncoding.EncodeToString(salt),
		Ciphertext: base64.StdEncoding.EncodeToString(ciphertext),
	}, nil
}

// DecryptKeystore decrypts a keystore using the provided password
func DecryptKeystore(ks *EncryptedKeystore, password []byte) ([]byte, error) {
	if ks.Version != KeystoreVersion {
		return nil, errors.New("unsupported keystore version")
	}

	salt, err := base64.StdEncoding.DecodeString(ks.Salt)
	if err != nil {
		return nil, errors.New("invalid salt encoding")
	}

	ciphertext, err := base64.StdEncoding.DecodeString(ks.Ciphertext)
	if err != nil {
		return nil, errors.New("invalid ciphertext encoding")
	}

	key := DeriveKey(password, salt)
	return Decrypt(ciphertext, key)
}

// Marshal serializes the keystore to JSON
func (ks *EncryptedKeystore) Marshal() ([]byte, error) {
	return json.MarshalIndent(ks, "", "  ")
}

// UnmarshalKeystore deserializes JSON to a keystore
func UnmarshalKeystore(data []byte) (*EncryptedKeystore, error) {
	var ks EncryptedKeystore
	if err := json.Unmarshal(data, &ks); err != nil {
		return nil, err
	}
	return &ks, nil
}

// IsEncryptedKeystore checks if data is an encrypted keystore
func IsEncryptedKeystore(data []byte) bool {
	var ks EncryptedKeystore
	if err := json.Unmarshal(data, &ks); err != nil {
		return false
	}
	return ks.Version > 0 && ks.Salt != "" && ks.Ciphertext != ""
}
