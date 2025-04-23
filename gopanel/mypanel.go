package main

import (
	"archive/zip"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/dustin/go-humanize"
	"github.com/gin-gonic/gin"
)

// Generate a random 32-byte secret key for cookie signing
func generateSecretKey() []byte {
	key := make([]byte, 32)
	_, err := rand.Read(key)
	if err != nil {
		log.Fatalf("Failed to generate secret key: %v", err)
	}
	return key
}

// Configuration
const (
	AdminUsername   = "admin"
	AdminPassword   = "securePa$$word123"
	CookieName      = "session_token"
	OthersUsername  = ""
	OthersPassword  = ""
	OthersUsername1 = ""
	OthersPassword1 = ""
)

var (
	SecretKey = generateSecretKey() // for signing cookies
)

// FileUpload represents a single file upload record
type FileUpload struct {
	ID        string    `json:"id"`
	ClientIP  string    `json:"client_ip"`
	ZipName   string    `json:"zip_name"`
	FileSize  int64     `json:"file_size"`
	Timestamp time.Time `json:"timestamp"`
	FilePath  string    `json:"file_path"`
	FileList  []string  `json:"file_list"`
}

// FileManager handles file upload tracking
type FileManager struct {
	mu           sync.RWMutex
	uploads      []FileUpload
	uploadFolder string
}

// NewFileManager creates a new file manager
func NewFileManager(uploadFolder string) *FileManager {
	// Ensure upload folder exists
	os.MkdirAll(uploadFolder, 0755)

	return &FileManager{
		uploads:      []FileUpload{},
		uploadFolder: uploadFolder,
	}
}

// generateUniqueID creates a unique identifier for each upload
func generateUniqueID() string {
	b := make([]byte, 16)
	rand.Read(b)
	return hex.EncodeToString(b)
}

// listZipContents reads the contents of a zip file
func listZipContents(zipPath string) ([]string, error) {
	// Open the zip file
	r, err := zip.OpenReader(zipPath)
	if err != nil {
		return nil, err
	}
	defer r.Close()

	// Prepare a slice to store file names
	var fileList []string

	// Track folders to avoid duplicates
	folders := make(map[string]bool)

	// Iterate through the files in the archive
	for _, f := range r.File {
		// Check if it's a directory
		if f.FileInfo().IsDir() {
			folders[f.Name] = true
			fileList = append(fileList, fmt.Sprintf("📁 %s (directory)", f.Name))
		} else {
			// For files, also add parent directories if they're not already added
			dir := filepath.Dir(f.Name)
			if dir != "." && !folders[dir+"/"] {
				folders[dir+"/"] = true
				fileList = append(fileList, fmt.Sprintf("📁 %s (directory)", dir))
			}

			// Add the file itself
			fileList = append(fileList, fmt.Sprintf("📄 %s (%d bytes)", f.Name, f.UncompressedSize64))
		}
	}

	return fileList, nil
}

// AddUpload registers a new file upload
func (fm *FileManager) AddUpload(clientIP, zipName, filePath string, fileSize int64) *FileUpload {
	fm.mu.Lock()
	defer fm.mu.Unlock()

	// Try to list zip contents
	fileList, err := listZipContents(filePath)
	if err != nil {
		fileList = []string{"Unable to read zip contents"}
	}

	upload := &FileUpload{
		ID:        generateUniqueID(),
		ClientIP:  clientIP,
		ZipName:   zipName,
		FileSize:  fileSize,
		Timestamp: time.Now(),
		FilePath:  filePath,
		FileList:  fileList,
	}

	fm.uploads = append(fm.uploads, *upload)
	return upload
}

// GetUploads retrieves all file uploads
func (fm *FileManager) GetUploads() []FileUpload {
	fm.mu.RLock()
	defer fm.mu.RUnlock()
	return fm.uploads
}

// FindUploadByID finds a specific upload by its ID
func (fm *FileManager) FindUploadByID(id string) (*FileUpload, bool) {
	fm.mu.RLock()
	defer fm.mu.RUnlock()

	for _, upload := range fm.uploads {
		if upload.ID == id {
			return &upload, true
		}
	}
	return nil, false
}

// Create a secure signed cookie
func createSignedCookie(name, value string) *http.Cookie {
	// Create HMAC signature
	h := hmac.New(sha256.New, SecretKey)
	h.Write([]byte(value))
	signature := h.Sum(nil)

	// Combine value and signature
	signedValue := value + "." + base64.StdEncoding.EncodeToString(signature)

	return &http.Cookie{
		Name:     name,
		Value:    signedValue,
		Path:     "/",
		HttpOnly: true,
		MaxAge:   86400 * 7, // 7 days
	}
}

// Verify and extract value from a signed cookie
func verifySignedCookie(cookie *http.Cookie) (string, bool) {
	if cookie == nil {
		return "", false
	}

	// Split value and signature
	parts := string(cookie.Value)
	dotIndex := -1
	for i := len(parts) - 1; i >= 0; i-- {
		if parts[i] == '.' {
			dotIndex = i
			break
		}
	}

	if dotIndex == -1 {
		return "", false
	}

	value := parts[:dotIndex]
	signatureBase64 := parts[dotIndex+1:]

	// Decode the signature
	signature, err := base64.StdEncoding.DecodeString(signatureBase64)
	if err != nil {
		return "", false
	}

	// Compute expected signature
	h := hmac.New(sha256.New, SecretKey)
	h.Write([]byte(value))
	expectedSignature := h.Sum(nil)

	// Compare signatures (constant-time comparison)
	if hmac.Equal(signature, expectedSignature) {
		return value, true
	}

	return "", false
}

// Authentication middleware
func authMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Public routes that don't require authentication
		publicRoutes := map[string]bool{
			"/login": true,
			"/Login": true,
			"/LOGIN": true,
		}

		// Check if route is public
		if publicRoutes[c.Request.URL.Path] {
			c.Next()
			return
		}

		// Get auth cookie
		cookie, err := c.Request.Cookie(CookieName)
		if err != nil {
			c.Redirect(http.StatusFound, "/login")
			c.Abort()
			return
		}

		// Verify cookie
		user, valid := verifySignedCookie(cookie)
		if !valid || user != AdminUsername {
			c.Redirect(http.StatusFound, "/login")
			c.Abort()
			return
		}

		c.Next()
	}
}

func main() {
	// Set Gin to release mode in production
	// gin.SetMode(gin.ReleaseMode)

	// Initialize file manager
	fileManager := NewFileManager("./uploads")

	// Create router
	r := gin.Default()

	// Serve frontend
	r.LoadHTMLGlob("templates/*")
	r.Static("/static", "./static")

	// Login route (public)
	r.GET("/login", func(c *gin.Context) {
		c.HTML(http.StatusOK, "login.html", gin.H{})
	})

	// Login POST route
	r.POST("/login", func(c *gin.Context) {
		username := c.PostForm("username")
		password := c.PostForm("password")

		if username == AdminUsername && password == AdminPassword {
			// Create a secure session cookie
			cookie := createSignedCookie(CookieName, username)
			http.SetCookie(c.Writer, cookie)

			c.Redirect(http.StatusFound, "/")
			return
		}

		c.HTML(http.StatusUnauthorized, "login.html", gin.H{
			"error": "Invalid credentials",
		})
	})

	// Protected routes
	r.Use(authMiddleware())

	// Logout route
	r.GET("/logout", func(c *gin.Context) {
		// Clear the session cookie
		cookie := &http.Cookie{
			Name:     CookieName,
			Value:    "",
			Path:     "/",
			HttpOnly: true,
			MaxAge:   -1, // Delete immediately
		}
		http.SetCookie(c.Writer, cookie)

		c.Redirect(http.StatusFound, "/login")
	})

	// Home page route
	r.GET("/", func(c *gin.Context) {
		uploads := fileManager.GetUploads()

		// Prepare uploads with human-readable sizes
		formattedUploads := make([]gin.H, len(uploads))
		for i, upload := range uploads {
			formattedUploads[i] = gin.H{
				"id":        upload.ID,
				"client_ip": upload.ClientIP,
				"zip_name":  upload.ZipName,
				"file_size": humanize.Bytes(uint64(upload.FileSize)),
				"timestamp": upload.Timestamp.Format("2006-01-02 15:04:05"),
			}
		}

		c.HTML(http.StatusOK, "home.html", gin.H{
			"uploads": formattedUploads,
		})
	})

	// Logs page route
	r.GET("/logs", func(c *gin.Context) {
		uploads := fileManager.GetUploads()

		// Prepare uploads with human-readable sizes
		formattedUploads := make([]gin.H, len(uploads))
		for i, upload := range uploads {
			formattedUploads[i] = gin.H{
				"id":        upload.ID,
				"client_ip": upload.ClientIP,
				"zip_name":  upload.ZipName,
				"file_size": humanize.Bytes(uint64(upload.FileSize)),
				"timestamp": upload.Timestamp.Format("2006-01-02 15:04:05"),
				"file_list": upload.FileList,
			}
		}

		c.HTML(http.StatusOK, "index.html", gin.H{
			"uploads": formattedUploads,
		})
	})

	// Checker page route
	r.GET("/checker", func(c *gin.Context) {
		uploads := fileManager.GetUploads()

		// Prepare uploads with human-readable sizes and file lists
		formattedUploads := make([]gin.H, len(uploads))
		for i, upload := range uploads {
			formattedUploads[i] = gin.H{
				"id":        upload.ID,
				"client_ip": upload.ClientIP,
				"zip_name":  upload.ZipName,
				"file_size": humanize.Bytes(uint64(upload.FileSize)),
				"timestamp": upload.Timestamp.Format("2006-01-02 15:04:05"),
				"file_list": upload.FileList,
			}
		}

		c.HTML(http.StatusOK, "checker.html", gin.H{
			"uploads": formattedUploads,
		})
	})

	// File upload route
	r.POST("/upload", func(c *gin.Context) {
		// Get uploaded file
		file, err := c.FormFile("file")
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "No file uploaded"})
			return
		}

		// Generate unique filename
		filename := filepath.Join("uploads", generateUniqueID()+"_"+file.Filename)

		// Save file
		if err := c.SaveUploadedFile(file, filename); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to save file"})
			return
		}

		// Get file info
		fileInfo, _ := os.Stat(filename)

		// Add to file manager
		upload := fileManager.AddUpload(c.ClientIP(), file.Filename, filename, fileInfo.Size())

		c.JSON(http.StatusOK, gin.H{
			"message": "File uploaded successfully",
			"file_id": upload.ID,
		})
	})

	// File download route
	r.GET("/download/:id", func(c *gin.Context) {
		id := c.Param("id")

		upload, found := fileManager.FindUploadByID(id)
		if !found {
			c.JSON(http.StatusNotFound, gin.H{"error": "File not found"})
			return
		}

		c.File(upload.FilePath)
	})

	// Start server
	port := 8080
	fmt.Printf("Server starting on port %d\n", port)
	log.Fatal(r.Run(fmt.Sprintf(":%d", port)))
}
