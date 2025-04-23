package history

import (
	"database/sql"
	"encoding/csv"
	"fmt"
	"io"
	"os"
	"os/user"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"

	_ "github.com/mattn/go-sqlite3"
)

// HistoryEntry represents a single browsing history record
type HistoryEntry struct {
	URL           string
	Title         string
	VisitCount    int
	LastVisitTime time.Time
}

// GetBrowserHistoryPath returns the file path for a browser's history database
func GetBrowserHistoryPath(browser string) string {
	currentUser, err := user.Current()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error getting current user: %v\n", err)
		return ""
	}
	username := currentUser.Username

	// Get last part of username (strip domain for Windows)
	for i := len(username) - 1; i >= 0; i-- {
		if username[i] == '\\' {
			username = username[i+1:]
			break
		}
	}

	switch runtime.GOOS {
	case "windows":
		if browser == "brave" || browser == "chrome" {
			// Try Brave first
			bravePath := filepath.Join("C:\\Users", username, "AppData", "Local", "BraveSoftware", "Brave-Browser", "User Data", "Default", "History")
			if _, err := os.Stat(bravePath); err == nil {
				return bravePath
			}
			// Fall back to Chrome
			return filepath.Join("C:\\Users", username, "AppData", "Local", "Google", "Chrome", "User Data", "Default", "History")
		} else if browser == "edge" {
			return filepath.Join("C:\\Users", username, "AppData", "Local", "Microsoft", "Edge", "User Data", "Default", "History")
		} else if browser == "firefox" {
			// Firefox is more complex as we need to find the profile directory
			firefoxDir := filepath.Join("C:\\Users", username, "AppData", "Roaming", "Mozilla", "Firefox", "Profiles")
			return findFirefoxProfile(firefoxDir)
		}

	case "darwin": // macOS
		if browser == "brave" || browser == "chrome" {
			// Try Brave first
			bravePath := filepath.Join("/Users", username, "Library", "Application Support", "BraveSoftware", "Brave-Browser", "Default", "History")
			if _, err := os.Stat(bravePath); err == nil {
				return bravePath
			}
			// Fall back to Chrome
			return filepath.Join("/Users", username, "Library", "Application Support", "Google", "Chrome", "Default", "History")
		} else if browser == "edge" {
			return filepath.Join("/Users", username, "Library", "Application Support", "Microsoft", "Edge", "Default", "History")
		} else if browser == "firefox" {
			firefoxDir := filepath.Join("/Users", username, "Library", "Application Support", "Firefox", "Profiles")
			return findFirefoxProfile(firefoxDir)
		}

	case "linux":
		if browser == "brave" || browser == "chrome" {
			// Try Brave first
			bravePath := filepath.Join("/home", username, ".config", "BraveSoftware", "Brave-Browser", "Default", "History")
			if _, err := os.Stat(bravePath); err == nil {
				return bravePath
			}
			// Fall back to Chrome
			return filepath.Join("/home", username, ".config", "google-chrome", "Default", "History")
		} else if browser == "edge" {
			return filepath.Join("/home", username, ".config", "microsoft-edge", "Default", "History")
		} else if browser == "firefox" {
			firefoxDir := filepath.Join("/home", username, ".mozilla", "firefox")
			return findFirefoxProfile(firefoxDir)
		}
	}

	return ""
}

// findFirefoxProfile attempts to locate the Firefox profile directory
func findFirefoxProfile(profilesDir string) string {
	if _, err := os.Stat(profilesDir); os.IsNotExist(err) {
		return ""
	}

	entries, err := os.ReadDir(profilesDir)
	if err != nil {
		return ""
	}

	// Look for default profile
	for _, entry := range entries {
		if entry.IsDir() && strings.Contains(entry.Name(), "default-release") {
			return filepath.Join(profilesDir, entry.Name(), "places.sqlite")
		}
	}

	// If default profile not found, use any available profile
	for _, entry := range entries {
		if entry.IsDir() && strings.HasSuffix(entry.Name(), ".default") {
			return filepath.Join(profilesDir, entry.Name(), "places.sqlite")
		}
	}

	return ""
}

// ExtractHistory extracts the browsing history from a specific browser
func ExtractHistory(browser string) ([]HistoryEntry, error) {
	historyPath := GetBrowserHistoryPath(browser)
	if historyPath == "" || !fileExists(historyPath) {
		return nil, fmt.Errorf("history file for %s not found", browser)
	}

	// Create a temporary copy of the history database
	tempHistoryPath := "temp_history.db"
	if err := copyFile(historyPath, tempHistoryPath); err != nil {
		return nil, fmt.Errorf("failed to copy history database: %v", err)
	}
	defer os.Remove(tempHistoryPath)

	if browser == "firefox" {
		// Firefox uses a different schema
		return extractFirefoxHistory(tempHistoryPath)
	} else {
		// Chrome, Brave, Edge use the same schema
		return extractChromiumHistory(tempHistoryPath)
	}
}

// extractChromiumHistory extracts history from Chromium-based browsers
func extractChromiumHistory(dbPath string) ([]HistoryEntry, error) {
	db, err := sql.Open("sqlite3", dbPath)
	if err != nil {
		return nil, err
	}
	defer db.Close()

	query := `
		SELECT
			urls.url,
			urls.title,
			urls.visit_count,
			urls.last_visit_time
		FROM
			urls
		ORDER BY
			last_visit_time DESC;
	`

	rows, err := db.Query(query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var entries []HistoryEntry

	for rows.Next() {
		var entry HistoryEntry
		var lastVisitTimeChrome int64

		if err := rows.Scan(&entry.URL, &entry.Title, &entry.VisitCount, &lastVisitTimeChrome); err != nil {
			fmt.Printf("Error scanning row: %v\n", err)
			continue
		}

		if lastVisitTimeChrome > 0 {
			// Convert Chrome timestamp (microseconds since 1601-01-01) to Go time
			// First, convert to Unix timestamp (seconds since 1970-01-01)
			unixTimeMicro := (lastVisitTimeChrome / 1000000) - 11644473600
			entry.LastVisitTime = time.Unix(unixTimeMicro, 0)
		}

		entries = append(entries, entry)
	}

	return entries, nil
}

// extractFirefoxHistory extracts history from Firefox
func extractFirefoxHistory(dbPath string) ([]HistoryEntry, error) {
	db, err := sql.Open("sqlite3", dbPath)
	if err != nil {
		return nil, err
	}
	defer db.Close()

	query := `
		SELECT
			moz_places.url,
			moz_places.title,
			moz_places.visit_count,
			moz_historyvisits.visit_date
		FROM
			moz_places
		JOIN
			moz_historyvisits ON moz_places.id = moz_historyvisits.place_id
		ORDER BY
			moz_historyvisits.visit_date DESC;
	`

	rows, err := db.Query(query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var entries []HistoryEntry

	for rows.Next() {
		var entry HistoryEntry
		var lastVisitTimeMozilla int64

		if err := rows.Scan(&entry.URL, &entry.Title, &entry.VisitCount, &lastVisitTimeMozilla); err != nil {
			fmt.Printf("Error scanning row: %v\n", err)
			continue
		}

		if lastVisitTimeMozilla > 0 {
			// Convert Mozilla timestamp (microseconds since 1970-01-01) to Go time
			entry.LastVisitTime = time.Unix(lastVisitTimeMozilla/1000000, 0)
		}

		entries = append(entries, entry)
	}

	return entries, nil
}

// SaveHistoryToCSV saves a slice of HistoryEntry to a CSV file
func SaveHistoryToCSV(entries []HistoryEntry, filePath string) error {
	file, err := os.Create(filePath)
	if err != nil {
		return err
	}
	defer file.Close()

	writer := csv.NewWriter(file)
	defer writer.Flush()

	// Write header
	if err := writer.Write([]string{"URL", "Title", "Visit Count", "Last Visit Time"}); err != nil {
		return err
	}

	// Write entries
	for _, entry := range entries {
		record := []string{
			entry.URL,
			entry.Title,
			strconv.Itoa(entry.VisitCount),
			entry.LastVisitTime.Format(time.RFC3339),
		}
		if err := writer.Write(record); err != nil {
			return err
		}
	}

	return nil
}

// ExtractAllBrowsersHistory extracts history from all supported browsers
func ExtractAllBrowsersHistory() error {
	// Create history directory if it doesn't exist
	if err := os.MkdirAll("Results", 0755); err != nil {
		return fmt.Errorf("failed to create history directory: %v", err)
	}

	browsers := []string{"chrome", "brave", "edge", "firefox"}
	var allEntries []HistoryEntry

	for _, browser := range browsers {
		fmt.Printf("Extracting history from %s...\n", browser)

		entries, err := ExtractHistory(browser)
		if err != nil {
			fmt.Printf("Error extracting %s history: %v\n", browser, err)
			continue
		}

		if len(entries) > 0 {
			// Save browser-specific history
			csvPath := filepath.Join("Results", fmt.Sprintf("%s_history.csv", browser))
			if err := SaveHistoryToCSV(entries, csvPath); err != nil {
				fmt.Printf("Error saving %s history: %v\n", browser, err)
			} else {
				fmt.Printf("Saved %d entries to %s\n", len(entries), csvPath)
			}

			// Add to combined history
			allEntries = append(allEntries, entries...)
		}
	}

	// Save combined history
	if len(allEntries) > 0 {
		csvPath := filepath.Join("Results", "combined_history.csv")
		if err := SaveHistoryToCSV(allEntries, csvPath); err != nil {
			return fmt.Errorf("error saving combined history: %v", err)
		}
		fmt.Printf("Combined history with %d entries saved to %s\n", len(allEntries), csvPath)
	}

	return nil
}

// Helper functions

// fileExists checks if a file exists
func fileExists(filePath string) bool {
	info, err := os.Stat(filePath)
	if os.IsNotExist(err) {
		return false
	}
	return !info.IsDir()
}

// copyFile copies a file from src to dst
func copyFile(src, dst string) error {
	sourceFile, err := os.Open(src)
	if err != nil {
		return err
	}
	defer sourceFile.Close()

	destFile, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer destFile.Close()

	_, err = io.Copy(destFile, sourceFile)
	return err
}
