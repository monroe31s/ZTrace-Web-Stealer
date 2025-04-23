package searchandcopy

import (
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

// FileTypes to search for
var targetFileTypes = map[string]bool{
	".txt":  true,
	".pdf":  true,
	".xll":  true,
	".xls":  true,
	".doc":  true,
	".docx": true,
	".pfx":  true,
}

// SearchAndCopyFiles searches for specific file types on desktop and copies them to Results folder
func SearchAndCopyFiles() error {
	// Create Results directory if it doesn't exist
	resultsDir := "Results"
	err := os.MkdirAll(resultsDir, os.ModePerm)
	if err != nil {
		return fmt.Errorf("failed to create Results directory: %v", err)
	}

	// Get desktop path
	desktopPath, err := getDesktopPath()
	if err != nil {
		return fmt.Errorf("failed to get desktop path: %v", err)
	}

	// Track copied files
	copiedFiles := 0

	// Read desktop directory entries
	entries, err := os.ReadDir(desktopPath)
	if err != nil {
		return fmt.Errorf("failed to read desktop directory: %v", err)
	}

	// Process files on desktop
	for _, entry := range entries {
		// Skip directories
		if entry.IsDir() {
			continue
		}

		// Get full path
		path := filepath.Join(desktopPath, entry.Name())

		// Check if file has target extension
		if isTargetFileType(path) {
			// Generate unique filename in Results folder
			fileName := entry.Name()
			destPath := filepath.Join(resultsDir, generateUniqueFileName(resultsDir, fileName))

			// Copy file
			if err := copyFile(path, destPath); err != nil {
				log.Printf("Failed to copy file %s: %v", path, err)
				continue
			}

			copiedFiles++
			fmt.Printf("Copied: %s\n", path)
		}
	}

	fmt.Printf("Total files copied: %d\n", copiedFiles)
	return nil
}

// getDesktopPath returns the path to the user's desktop
func getDesktopPath() (string, error) {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}

	var desktopPath string
	switch runtime.GOOS {
	case "windows":
		desktopPath = filepath.Join(homeDir, "Desktop")
	case "darwin":
		desktopPath = filepath.Join(homeDir, "Desktop")
	case "linux":
		desktopPath = filepath.Join(homeDir, "Desktop")
	default:
		return "", fmt.Errorf("unsupported operating system")
	}

	return desktopPath, nil
}

// isTargetFileType checks if the file has a target extension
func isTargetFileType(path string) bool {
	ext := strings.ToLower(filepath.Ext(path))
	return targetFileTypes[ext]
}

// copyFile copies a file from source to destination
func copyFile(src, dst string) error {
	// Open source file
	sourceFile, err := os.Open(src)
	if err != nil {
		return err
	}
	defer sourceFile.Close()

	// Create destination file
	destFile, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer destFile.Close()

	// Copy file contents
	_, err = io.Copy(destFile, sourceFile)
	return err
}

// generateUniqueFileName ensures no filename conflicts in destination
func generateUniqueFileName(dir, fileName string) string {
	ext := filepath.Ext(fileName)
	base := strings.TrimSuffix(fileName, ext)
	newPath := filepath.Join(dir, fileName)

	counter := 1
	for fileExists(newPath) {
		newFileName := fmt.Sprintf("%s_%d%s", base, counter, ext)
		newPath = filepath.Join(dir, newFileName)
		counter++
	}

	return filepath.Base(newPath)
}

// fileExists checks if a file exists
func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}
