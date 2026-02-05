package utils

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/ethereum/go-ethereum/ethclient"
	"github.com/tokamak-network/trh-sdk/pkg/crypto"
	"github.com/tokamak-network/trh-sdk/pkg/types"
)

// cachedPassword stores the decryption password in memory during the session.
// This is used to re-encrypt the config when saving updates.
// The password is never written to disk.
var cachedPassword []byte

// GetCachedPassword returns the cached password for re-encryption.
// Returns nil if no password has been cached (i.e., config was not encrypted).
func GetCachedPassword() []byte {
	return cachedPassword
}

// ClearCachedPassword clears the cached password from memory.
func ClearCachedPassword() {
	cachedPassword = nil
}

// IsConfigEncrypted checks if the settings file at the given path is encrypted.
func IsConfigEncrypted(deploymentPath string) bool {
	filePath := fmt.Sprintf("%s/%s", deploymentPath, types.ConfigFileName)
	data, err := os.ReadFile(filePath)
	if err != nil {
		return false
	}
	return crypto.IsEncryptedKeystore(data)
}

func CopyFile(src, dst string) error {
	// Open the source file
	sourceFile, err := os.Open(src)
	if err != nil {
		return fmt.Errorf("failed to open source file: %v", err)
	}
	defer sourceFile.Close()

	// Ensure destination directory exists
	if err := os.MkdirAll(filepath.Dir(dst), 0755); err != nil {
		return fmt.Errorf("failed to create destination directory: %v", err)
	}

	// Create the destination file
	destinationFile, err := os.Create(dst)
	if err != nil {
		return fmt.Errorf("failed to create destination file: %v", err)
	}
	defer destinationFile.Close()

	// Copy content
	if _, err := io.Copy(destinationFile, sourceFile); err != nil {
		return fmt.Errorf("failed to copy content: %v", err)
	}

	// Preserve file permissions
	info, err := os.Stat(src)
	if err != nil {
		return fmt.Errorf("failed to stat source file: %v", err)
	}
	if err := os.Chmod(dst, info.Mode()); err != nil {
		return fmt.Errorf("failed to set destination file permissions: %v", err)
	}

	return nil
}

func CheckFileExists(filePath string) bool {
	_, err := os.Stat(filePath)
	// If the error is nil, the file exists
	if err == nil {
		return true
	}
	// If the error is not nil, check if it's a "file not found" error
	if os.IsNotExist(err) {
		return false
	}
	// Return false in case of other errors
	return false
}

func CheckDirExists(path string) bool {
	info, err := os.Stat(path)
	if err != nil {
		if os.IsNotExist(err) {
			return false
		}
		fmt.Println("Error checking directory:", err)
		return false
	}
	return info.IsDir()
}

func ReadConfigFromJSONFile(deploymentPath string) (*types.Config, error) {

	filePath := fmt.Sprintf("%s/%s", deploymentPath, types.ConfigFileName)

	fmt.Println("Reading config from:", filePath)

	fileExist := CheckFileExists(filePath)
	if !fileExist {
		return nil, nil
	}

	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, err
	}

	var config types.Config

	// Check if settings are encrypted
	if isEncryptedSettings(data) {
		// Get password from env or prompt
		password, err := getSettingsPassword()
		if err != nil {
			return nil, fmt.Errorf("failed to get password: %w", err)
		}

		// Decrypt the settings
		decrypted, err := decryptSettings(data, password)
		if err != nil {
			return nil, fmt.Errorf("decryption failed: %w", err)
		}

		if err := json.Unmarshal(decrypted, &config); err != nil {
			return nil, err
		}
	} else {
		// Plain JSON - unmarshal directly
		if err := json.Unmarshal(data, &config); err != nil {
			return nil, err
		}
	}

	// If L2ChainId doesn't exist, fetch it from the L2 RPC
	if config.L2ChainID == 0 && config.L2RpcUrl != "" {
		l2Provider, err := ethclient.Dial(config.L2RpcUrl)
		if err != nil {
			fmt.Println("Error connecting to L2 blockchain:", err)
			return nil, err
		}

		chainId, err := l2Provider.ChainID(context.Background())
		if err != nil || chainId == nil {
			fmt.Println("Error getting L2 chain id:", err)
			return nil, err
		}
		config.L2ChainID = chainId.Uint64()
	}

	return &config, nil
}

func ReadDeployementConfigFromJSONFile(deploymentPath string, chainId uint64) (*types.Contracts, error) {
	filePath := fmt.Sprintf("%s/tokamak-thanos/packages/tokamak/contracts-bedrock/deployments/%s", deploymentPath, fmt.Sprintf("%d-deploy.json", chainId))

	fileExist := CheckFileExists(filePath)
	if !fileExist {
		return nil, fmt.Errorf("deployment file does not exist: %s", filePath)
	}

	file, err := os.Open(filePath)
	if err != nil {
		fmt.Println("Error opening deployment file:", err)
		return nil, err
	}
	defer file.Close()

	var contracts types.Contracts
	decoder := json.NewDecoder(file)
	if err := decoder.Decode(&contracts); err != nil {
		fmt.Println("Error decoding deployment JSON file:", err)
		return nil, err
	}
	return &contracts, nil
}

func ReadMetadataInfoFromJSONFile(deploymentPath string, chainId uint64) (*types.MetadataInfo, error) {
	filePath := fmt.Sprintf("%s/%s", deploymentPath, types.MetadataInfoFileName)

	fileExist := CheckFileExists(filePath)
	if !fileExist {
		return &types.MetadataGenericInfo, nil
	}

	file, err := os.Open(filePath)
	if err != nil {
		fmt.Println("Error opening metadata info file:", err)
		return nil, err
	}
	defer file.Close()

	var metadataInfo types.MetadataInfo
	decoder := json.NewDecoder(file)
	if err := decoder.Decode(&metadataInfo); err != nil {
		fmt.Println("Error decoding metadata info JSON file:", err)
		return nil, err
	}
	return &metadataInfo, nil
}

// isEncryptedSettings checks if the settings file is encrypted
func isEncryptedSettings(data []byte) bool {
	return crypto.IsEncryptedKeystore(data)
}

// getSettingsPassword gets password from env var or prompts user.
// The password is cached in memory for re-encryption when saving config.
func getSettingsPassword() ([]byte, error) {
	password, err := crypto.GetPasswordFromEnvOrPrompt(
		crypto.PasswordEnvVar,
		"Enter settings password: ",
	)
	if err != nil {
		return nil, err
	}
	// Cache the password for later use when saving config
	cachedPassword = password
	return password, nil
}

// decryptSettings decrypts the encrypted settings data
func decryptSettings(data, password []byte) ([]byte, error) {
	ks, err := crypto.UnmarshalKeystore(data)
	if err != nil {
		return nil, err
	}
	return crypto.DecryptKeystore(ks, password)
}

// EncryptAndSaveConfig encrypts and saves config to settings.json
func EncryptAndSaveConfig(deploymentPath string, config *types.Config, password []byte) error {
	return crypto.WriteEncryptedConfig(deploymentPath, config, password)
}

// WriteConfigToJSONFile writes config to settings.json, preserving encryption if it was encrypted.
// If the original file was encrypted and we have the cached password, the output will be encrypted.
// Otherwise, it writes plaintext JSON.
func WriteConfigToJSONFile(deploymentPath string, config *types.Config) error {
	// Check if we should preserve encryption
	if cachedPassword != nil && IsConfigEncrypted(deploymentPath) {
		return crypto.WriteEncryptedConfig(deploymentPath, config, cachedPassword)
	}

	// Check if password is cached but file doesn't exist yet (first write after encryption was enabled)
	if cachedPassword != nil {
		return crypto.WriteEncryptedConfig(deploymentPath, config, cachedPassword)
	}

	// Write plaintext JSON
	data, err := json.MarshalIndent(config, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal config: %w", err)
	}

	fileName := filepath.Join(deploymentPath, types.ConfigFileName)
	if err := os.WriteFile(fileName, data, types.SecureFileMode); err != nil {
		return fmt.Errorf("failed to write config: %w", err)
	}

	return nil
}
