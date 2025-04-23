package downloads

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	_ "github.com/mattn/go-sqlite3"
)

// DownloadInfo represents a single download entry
type DownloadInfo struct {
	ID          int64  `json:"id"`
	CurrentPath string `json:"current_path"`
	TargetPath  string `json:"target_path"`
	StartTime   string `json:"start_time"`
	URL         string `json:"url"`
}

// GetBrowserDownloadDB returns the path to the browser's download database
func GetBrowserDownloadDB(browserName string) (string, error) {
	usr, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("error getting user home directory: %v", err)
	}

	var dbPath string
	switch browserName {
	case "chrome":
		dbPath = filepath.Join(usr, "AppData", "Local", "Google", "Chrome", "User Data", "Default", "History")
	case "brave":
		dbPath = filepath.Join(usr, "AppData", "Local", "BraveSoftware", "Brave-Browser", "User Data", "Default", "History")
	case "edge":
		dbPath = filepath.Join(usr, "AppData", "Local", "Microsoft", "Edge", "User Data", "Default", "History")
	case "firefox":
		// Firefox store data in random profile folders, need to find it
		profilesDir := filepath.Join(usr, "AppData", "Roaming", "Mozilla", "Firefox", "Profiles")

		// Check if directory exists
		if _, err := os.Stat(profilesDir); os.IsNotExist(err) {
			return "", fmt.Errorf("firefox profiles directory not found")
		}

		// Find profile directory that ends with .default-release
		entries, err := os.ReadDir(profilesDir)
		if err != nil {
			return "", fmt.Errorf("error reading firefox profiles directory: %v", err)
		}

		// Look for default profile directory
		for _, entry := range entries {
			if entry.IsDir() {
				if filepath.Ext(entry.Name()) == ".default-release" || filepath.Ext(entry.Name()) == ".default" {
					dbPath = filepath.Join(profilesDir, entry.Name(), "places.sqlite")
					if _, err := os.Stat(dbPath); err == nil {
						return dbPath, nil
					}
				}
			}
		}
		return "", fmt.Errorf("firefox downloads database not found")
	default:
		return "", fmt.Errorf("unsupported browser: %s", browserName)
	}

	// Check if the database file exists
	if _, err := os.Stat(dbPath); os.IsNotExist(err) {
		return "", fmt.Errorf("downloads database not found for %s", browserName)
	}

	return dbPath, nil
}

// CopyDBToTemp makes a temporary copy of the database file to avoid locking issues
func CopyDBToTemp(dbPath string) (string, error) {
	// Create a temporary file
	tempDBPath := filepath.Join(filepath.Dir(dbPath), "temp_history.db")

	// Remove any existing temp file
	os.Remove(tempDBPath)

	// Copy the database
	srcFile, err := os.Open(dbPath)
	if err != nil {
		return "", fmt.Errorf("error opening database file: %v", err)
	}
	defer srcFile.Close()

	dstFile, err := os.Create(tempDBPath)
	if err != nil {
		return "", fmt.Errorf("error creating temporary database file: %v", err)
	}
	defer dstFile.Close()

	_, err = io.Copy(dstFile, srcFile)
	if err != nil {
		return "", fmt.Errorf("error copying database file: %v", err)
	}

	return tempDBPath, nil
}

// ExtractDownloadHistoryFromBrowser extracts download history from a specific browser
func ExtractDownloadHistoryFromBrowser(browser string) ([]DownloadInfo, error) {
	var downloads []DownloadInfo

	// Get database path
	dbPath, err := GetBrowserDownloadDB(browser)
	if err != nil {
		return nil, err
	}

	// Create a temporary copy of the database
	tempDBPath, err := CopyDBToTemp(dbPath)
	if err != nil {
		return nil, err
	}
	defer os.Remove(tempDBPath)

	// Connect to the database
	db, err := sql.Open("sqlite3", tempDBPath)
	if err != nil {
		return nil, fmt.Errorf("error opening database: %v", err)
	}
	defer db.Close()

	// Query the database
	var query string
	if browser == "firefox" {
		query = "SELECT id, current_path, target_path, start_time, url FROM moz_downloads"
	} else {
		query = "SELECT id, current_path, target_path, start_time, site_url FROM downloads"
	}

	rows, err := db.Query(query)
	if err != nil {
		return nil, fmt.Errorf("error querying database: %v", err)
	}
	defer rows.Close()

	// Process the results
	for rows.Next() {
		var download DownloadInfo
		var startTime int64

		if err := rows.Scan(&download.ID, &download.CurrentPath, &download.TargetPath, &startTime, &download.URL); err != nil {
			fmt.Printf("Error scanning row: %v\n", err)
			continue
		}

		// Convert the timestamp to a readable format
		// Chrome-based browsers store time as microseconds since 1601-01-01
		if startTime > 0 {
			if browser == "firefox" {
				// Firefox stores time as microseconds since 1970-01-01
				download.StartTime = time.Unix(startTime/1000000, 0).UTC().Format("2006-01-02 15:04:05")
			} else {
				// Chrome-based browsers store time as microseconds since 1601-01-01
				// Need to convert to Unix timestamp (seconds since 1970-01-01)
				unixTime := (startTime / 1000000) - 11644473600
				download.StartTime = time.Unix(unixTime, 0).UTC().Format("2006-01-02 15:04:05")
			}
		}

		downloads = append(downloads, download)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating over rows: %v", err)
	}

	return downloads, nil
}

// ExtractDownloadHistoryFromAllBrowsers extracts download history from all supported browsers
func ExtractDownloadHistoryFromAllBrowsers() (map[string][]DownloadInfo, error) {
	browsers := []string{"chrome", "brave", "edge", "firefox"}
	allDownloadData := make(map[string][]DownloadInfo)

	for _, browser := range browsers {
		fmt.Printf("[+] Extracting %s download history...\n", browser)

		downloads, err := ExtractDownloadHistoryFromBrowser(browser)
		if err != nil {
			fmt.Printf("[-] Error with %s: %v\n", browser, err)
			continue
		}

		if len(downloads) > 0 {
			allDownloadData[browser] = downloads
			fmt.Printf("[+] Extracted %d downloads from %s\n", len(downloads), browser)
		} else {
			fmt.Printf("[-] No download history found for %s\n", browser)
		}
	}

	return allDownloadData, nil
}

// SaveDownloadHistory saves download history to a JSON file
func SaveDownloadHistory(downloads map[string][]DownloadInfo, outputPath string) error {
	// Create directory if it doesn't exist
	dir := filepath.Dir(outputPath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("error creating directory: %v", err)
	}

	// Create the output file
	file, err := os.Create(outputPath)
	if err != nil {
		return fmt.Errorf("error creating output file: %v", err)
	}
	defer file.Close()

	// Encode the data as JSON
	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "    ")

	if err := encoder.Encode(downloads); err != nil {
		return fmt.Errorf("error encoding JSON: %v", err)
	}

	return nil
}

// ExtractDownloads is the main function to extract download history and save it to a file
func ExtractDownloads() error {
	// Create results directory
	resultsDir := "Results"
	if err := os.MkdirAll(resultsDir, 0755); err != nil {
		return fmt.Errorf("error creating results directory: %v", err)
	}

	// Extract download history
	downloadHistory, err := ExtractDownloadHistoryFromAllBrowsers()
	if err != nil {
		return fmt.Errorf("error extracting download history: %v", err)
	}

	// Check if we found any downloads
	totalDownloads := 0
	for _, downloads := range downloadHistory {
		totalDownloads += len(downloads)
	}

	if totalDownloads == 0 {
		fmt.Println("[-] No download history found in any browser")
		return nil
	}

	// Save download history to file
	outputPath := filepath.Join(resultsDir, "download_history.json")
	if err := SaveDownloadHistory(downloadHistory, outputPath); err != nil {
		return fmt.Errorf("error saving download history: %v", err)
	}

	fmt.Printf("[+] Successfully extracted %d downloads from %d browsers\n", totalDownloads, len(downloadHistory))
	fmt.Printf("[+] Download history saved to %s\n", outputPath)

	return nil
}
