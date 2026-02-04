package crypto

import (
	"errors"
	"fmt"
	"os"

	"golang.org/x/term"
)

// PromptPassword prompts the user for a password with hidden input
func PromptPassword(prompt string) ([]byte, error) {
	fmt.Print(prompt)

	// Read password with echo disabled
	password, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Println() // Add newline after hidden input

	if err != nil {
		return nil, err
	}

	if len(password) == 0 {
		return nil, errors.New("password cannot be empty")
	}

	return password, nil
}

// PromptPasswordConfirm prompts for password with confirmation
func PromptPasswordConfirm(prompt, confirmPrompt string) ([]byte, error) {
	password, err := PromptPassword(prompt)
	if err != nil {
		return nil, err
	}

	confirm, err := PromptPassword(confirmPrompt)
	if err != nil {
		return nil, err
	}

	if string(password) != string(confirm) {
		return nil, errors.New("passwords do not match")
	}

	return password, nil
}

// GetPasswordFromEnvOrPrompt checks env var first, then prompts
func GetPasswordFromEnvOrPrompt(envVar, prompt string) ([]byte, error) {
	if pw := os.Getenv(envVar); pw != "" {
		return []byte(pw), nil
	}
	return PromptPassword(prompt)
}

// PasswordEnvVar is the environment variable for CI/CD password
const PasswordEnvVar = "TRH_SETTINGS_PASSWORD"
