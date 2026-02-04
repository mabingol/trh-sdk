package crypto

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

// ConfigFileName is the name of the settings file
const ConfigFileName = "settings.json"

// WriteEncryptedConfig writes config data encrypted with password
func WriteEncryptedConfig(deploymentPath string, config interface{}, password []byte) error {
	// Marshal config to JSON
	data, err := json.MarshalIndent(config, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal config: %w", err)
	}

	// Encrypt the JSON data
	ks, err := EncryptToKeystore(data, password)
	if err != nil {
		return fmt.Errorf("failed to encrypt config: %w", err)
	}

	// Marshal the keystore
	encrypted, err := ks.Marshal()
	if err != nil {
		return fmt.Errorf("failed to marshal keystore: %w", err)
	}

	// Write to file with secure permissions
	fileName := filepath.Join(deploymentPath, ConfigFileName)
	if err := os.WriteFile(fileName, encrypted, 0600); err != nil {
		return fmt.Errorf("failed to write encrypted config: %w", err)
	}

	return nil
}

// ReadEncryptedConfig reads and decrypts config data
func ReadEncryptedConfig(deploymentPath string, password []byte, config interface{}) error {
	fileName := filepath.Join(deploymentPath, ConfigFileName)

	// Read the file
	data, err := os.ReadFile(fileName)
	if err != nil {
		return fmt.Errorf("failed to read config file: %w", err)
	}

	// Check if it's encrypted
	if !IsEncryptedKeystore(data) {
		// Plain JSON - just unmarshal directly
		if err := json.Unmarshal(data, config); err != nil {
			return fmt.Errorf("failed to parse config: %w", err)
		}
		return nil
	}

	// Decrypt the keystore
	ks, err := UnmarshalKeystore(data)
	if err != nil {
		return fmt.Errorf("failed to parse encrypted config: %w", err)
	}

	plaintext, err := DecryptKeystore(ks, password)
	if err != nil {
		return fmt.Errorf("decryption failed: %w", err)
	}

	// Unmarshal the decrypted JSON
	if err := json.Unmarshal(plaintext, config); err != nil {
		return fmt.Errorf("failed to parse decrypted config: %w", err)
	}

	return nil
}

// IsConfigEncrypted checks if the settings file is encrypted
func IsConfigEncrypted(deploymentPath string) (bool, error) {
	fileName := filepath.Join(deploymentPath, ConfigFileName)

	data, err := os.ReadFile(fileName)
	if err != nil {
		if os.IsNotExist(err) {
			return false, nil
		}
		return false, err
	}

	return IsEncryptedKeystore(data), nil
}

// MigrateToEncrypted encrypts an existing plaintext config
func MigrateToEncrypted(deploymentPath string, password []byte) error {
	fileName := filepath.Join(deploymentPath, ConfigFileName)

	// Read existing config
	data, err := os.ReadFile(fileName)
	if err != nil {
		return fmt.Errorf("failed to read config: %w", err)
	}

	// Check if already encrypted
	if IsEncryptedKeystore(data) {
		return fmt.Errorf("config is already encrypted")
	}

	// Validate it's valid JSON
	var temp map[string]interface{}
	if err := json.Unmarshal(data, &temp); err != nil {
		return fmt.Errorf("invalid JSON config: %w", err)
	}

	// Encrypt
	ks, err := EncryptToKeystore(data, password)
	if err != nil {
		return fmt.Errorf("failed to encrypt: %w", err)
	}

	encrypted, err := ks.Marshal()
	if err != nil {
		return fmt.Errorf("failed to marshal keystore: %w", err)
	}

	// Write encrypted config
	if err := os.WriteFile(fileName, encrypted, 0600); err != nil {
		return fmt.Errorf("failed to write encrypted config: %w", err)
	}

	return nil
}
