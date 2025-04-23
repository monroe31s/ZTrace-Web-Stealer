package bookmarks

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
)

// Bookmark represents a browser bookmark entry
type Bookmark struct {
	Title string
	URL   string
}

// BookmarkNode represents a node in the bookmark hierarchy
type BookmarkNode struct {
	Children []struct {
		Name     string        `json:"name"`
		URL      string        `json:"url,omitempty"`
		Children []interface{} `json:"children,omitempty"`
	} `json:"children,omitempty"`
}

// BookmarkData represents the structure of the bookmarks file
type BookmarkData struct {
	Roots struct {
		BookmarkBar BookmarkNode `json:"bookmark_bar"`
		Other       BookmarkNode `json:"other"`
	} `json:"roots"`
}

// GetBookmarksPath returns the path to the bookmarks file for a browser
func GetBookmarksPath(browser string) string {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error getting user home directory: %v\n", err)
		return ""
	}

	var bookmarksPath string

	switch runtime.GOOS {
	case "windows":
		switch browser {
		case "brave":
			bookmarksPath = filepath.Join(homeDir, "AppData", "Local", "BraveSoftware", "Brave-Browser", "User Data", "Default", "Bookmarks")
		case "chrome":
			bookmarksPath = filepath.Join(homeDir, "AppData", "Local", "Google", "Chrome", "User Data", "Default", "Bookmarks")
		case "edge":
			bookmarksPath = filepath.Join(homeDir, "AppData", "Local", "Microsoft", "Edge", "User Data", "Default", "Bookmarks")
		}
	case "darwin": // macOS
		switch browser {
		case "brave":
			bookmarksPath = filepath.Join(homeDir, "Library", "Application Support", "BraveSoftware", "Brave-Browser", "Default", "Bookmarks")
		case "chrome":
			bookmarksPath = filepath.Join(homeDir, "Library", "Application Support", "Google", "Chrome", "Default", "Bookmarks")
		case "edge":
			bookmarksPath = filepath.Join(homeDir, "Library", "Application Support", "Microsoft Edge", "Default", "Bookmarks")
		}
	case "linux":
		switch browser {
		case "brave":
			bookmarksPath = filepath.Join(homeDir, ".config", "BraveSoftware", "Brave-Browser", "Default", "Bookmarks")
		case "chrome":
			bookmarksPath = filepath.Join(homeDir, ".config", "google-chrome", "Default", "Bookmarks")
		case "edge":
			bookmarksPath = filepath.Join(homeDir, ".config", "microsoft-edge", "Default", "Bookmarks")
		}
	}

	return bookmarksPath
}

// ParseBookmarkFolder recursively extracts bookmarks from a folder
func ParseBookmarkFolder(folder interface{}) []Bookmark {
	var bookmarks []Bookmark

	// Try to convert to map
	folderMap, ok := folder.(map[string]interface{})
	if !ok {
		return bookmarks
	}

	// Check if there are children
	children, ok := folderMap["children"].([]interface{})
	if !ok {
		return bookmarks
	}

	// Process each child
	for _, child := range children {
		childMap, ok := child.(map[string]interface{})
		if !ok {
			continue
		}

		// If the child has a URL, it's a bookmark
		if url, ok := childMap["url"].(string); ok {
			name, _ := childMap["name"].(string)
			bookmarks = append(bookmarks, Bookmark{
				Title: name,
				URL:   url,
			})
		}

		// If the child has children, recursively parse them
		if _, hasChildren := childMap["children"]; hasChildren {
			bookmarks = append(bookmarks, ParseBookmarkFolder(childMap)...)
		}
	}

	return bookmarks
}

// ExtractBookmarks extracts bookmarks from a specific browser
func ExtractBookmarks(browser string) ([]Bookmark, error) {
	bookmarksPath := GetBookmarksPath(browser)
	if bookmarksPath == "" || !fileExists(bookmarksPath) {
		return nil, fmt.Errorf("bookmarks file for %s not found at %s", browser, bookmarksPath)
	}

	// Read the bookmarks file
	data, err := os.ReadFile(bookmarksPath)
	if err != nil {
		return nil, fmt.Errorf("error reading bookmarks file: %v", err)
	}

	// Parse the JSON
	var bookmarksData BookmarkData
	if err := json.Unmarshal(data, &bookmarksData); err != nil {
		return nil, fmt.Errorf("error parsing bookmarks JSON: %v", err)
	}

	// Extract bookmarks from the bookmark bar and other folders
	var allBookmarks []Bookmark

	// Extract from bookmark bar
	bookmarkBar, err := json.Marshal(bookmarksData.Roots.BookmarkBar)
	if err == nil {
		var bookmarkBarNode map[string]interface{}
		if err := json.Unmarshal(bookmarkBar, &bookmarkBarNode); err == nil {
			allBookmarks = append(allBookmarks, ParseBookmarkFolder(bookmarkBarNode)...)
		}
	}

	// Extract from other bookmarks
	other, err := json.Marshal(bookmarksData.Roots.Other)
	if err == nil {
		var otherNode map[string]interface{}
		if err := json.Unmarshal(other, &otherNode); err == nil {
			allBookmarks = append(allBookmarks, ParseBookmarkFolder(otherNode)...)
		}
	}

	return allBookmarks, nil
}

// SaveBookmarksToCSV saves bookmarks to a CSV file
func SaveBookmarksToCSV(bookmarks []Bookmark, outputPath string) error {
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
	if err := writer.Write([]string{"Title", "URL"}); err != nil {
		return fmt.Errorf("error writing CSV header: %v", err)
	}

	// Write bookmarks
	for _, bookmark := range bookmarks {
		if err := writer.Write([]string{bookmark.Title, bookmark.URL}); err != nil {
			return fmt.Errorf("error writing bookmark to CSV: %v", err)
		}
	}

	return nil
}

// ExtractBookmarksFromAllBrowsers extracts bookmarks from all supported browsers
func ExtractBookmarksFromAllBrowsers() error {
	// Create results directory
	resultsDir := "Results"
	if err := os.MkdirAll(resultsDir, 0755); err != nil {
		return fmt.Errorf("error creating results directory: %v", err)
	}

	browsers := []string{"chrome", "brave", "edge"}
	totalBookmarks := 0

	for _, browser := range browsers {
		fmt.Printf("[+] Extracting bookmarks from %s...\n", browser)

		bookmarks, err := ExtractBookmarks(browser)
		if err != nil {
			fmt.Printf("[-] Error extracting %s bookmarks: %v\n", browser, err)
			continue
		}

		if len(bookmarks) > 0 {
			// Save browser-specific bookmarks
			outputPath := filepath.Join(resultsDir, fmt.Sprintf("%s_bookmarks.csv", browser))
			if err := SaveBookmarksToCSV(bookmarks, outputPath); err != nil {
				fmt.Printf("[-] Error saving %s bookmarks: %v\n", browser, err)
			} else {
				fmt.Printf("[+] Saved %d %s bookmarks to %s\n", len(bookmarks), browser, outputPath)
				totalBookmarks += len(bookmarks)
			}
		} else {
			fmt.Printf("[-] No bookmarks found for %s\n", browser)
		}
	}

	if totalBookmarks > 0 {
		fmt.Printf("[+] Successfully extracted a total of %d bookmarks\n", totalBookmarks)
	} else {
		fmt.Println("[-] No bookmarks found in any browser")
	}

	return nil
}

// Helper function to check if a file exists
func fileExists(filePath string) bool {
	info, err := os.Stat(filePath)
	if os.IsNotExist(err) {
		return false
	}
	return !info.IsDir()
}
