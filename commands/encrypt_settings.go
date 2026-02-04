package commands

import (
	"context"
	"fmt"
	"os"

	"github.com/urfave/cli/v3"

	"github.com/tokamak-network/trh-sdk/pkg/crypto"
	"github.com/tokamak-network/trh-sdk/pkg/types"
	"github.com/tokamak-network/trh-sdk/pkg/utils"
)

func ActionEncryptSettings() cli.ActionFunc {
	return func(ctx context.Context, cmd *cli.Command) error {
		deploymentPath, err := os.Getwd()
		if err != nil {
			return err
		}

		filePath := fmt.Sprintf("%s/%s", deploymentPath, types.ConfigFileName)

		// Check if file exists
		if !utils.CheckFileExists(filePath) {
			fmt.Println("Error: settings.json not found in current directory")
			return fmt.Errorf("settings.json not found")
		}

		// Read the file to check if already encrypted
		data, err := os.ReadFile(filePath)
		if err != nil {
			return fmt.Errorf("failed to read settings.json: %w", err)
		}

		if crypto.IsEncryptedKeystore(data) {
			fmt.Println("Settings are already encrypted")
			return nil
		}

		// Prompt for password with confirmation
		password, err := crypto.PromptPasswordConfirm(
			"Set encryption password: ",
			"Confirm password: ",
		)
		if err != nil {
			return fmt.Errorf("password error: %w", err)
		}

		// Migrate to encrypted format
		if err := crypto.MigrateToEncrypted(deploymentPath, password); err != nil {
			return fmt.Errorf("encryption failed: %w", err)
		}

		fmt.Println("✅ Settings encrypted successfully")
		return nil
	}
}
