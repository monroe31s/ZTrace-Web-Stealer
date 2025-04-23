package yandex_decrypt

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/x509"
	"database/sql"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"syscall"
	"unsafe"

	_ "github.com/mattn/go-sqlite3"
	"github.com/stretchr/objx"
	"golang.org/x/crypto/pbkdf2"
)

var (
	yandexSignature           = []byte{0x08, 0x01, 0x12, 0x20}
	errInvalidYandexSignature = errors.New("main: inavalidYandexSignature")
)

type yandexDecrypt struct {
	path     string
	key      []byte
	profiles []string
}

type sealedKey struct {
	encryptedEncryptionKey           []byte
	encryptedPrivateKey              []byte
	unlockKeySalt                    []byte
	encryptionKeyAlgorithm           int
	encryptionKeyEncryptionAlgorithm int
	keyId                            string
	privateKeyEncryptionAlgorithm    int
	unlockKeyDerivationAlgorithm     int
	unlockKeyIterations              int
}

type invalidMasterPasswordTypeError struct {
	message string
}

func (e *invalidMasterPasswordTypeError) Error() string {
	return fmt.Sprintf("main: %s", e.message)
}

func getSealedKey(db *sql.DB) (*sealedKey, error) {
	var sealedKeyJson string
	err := db.QueryRow("SELECT sealed_key FROM active_keys").Scan(&sealedKeyJson)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}

	sealedKeyObjx, err := objx.FromJSON(sealedKeyJson)
	if err != nil {
		return nil, err
	}

	encryptedEncryptionKey, err := base64.StdEncoding.DecodeString(sealedKeyObjx.Get("encrypted_encryption_key").Str())
	if err != nil {
		return nil, err
	}
	encryptedPrivateKey, err := base64.StdEncoding.DecodeString(sealedKeyObjx.Get("encrypted_private_key").Str())
	if err != nil {
		return nil, err
	}
	unlockKeySalt, err := base64.StdEncoding.DecodeString(sealedKeyObjx.Get("unlock_key_salt").Str())
	if err != nil {
		return nil, err
	}

	return &sealedKey{
		encryptedEncryptionKey,
		encryptedPrivateKey,
		unlockKeySalt,
		sealedKeyObjx.Get("encryption_key_algorithm").Int(),
		sealedKeyObjx.Get("encryption_key_encryption_algorithm").Int(),
		sealedKeyObjx.Get("key_id").Str(),
		sealedKeyObjx.Get("private_key_encryption_algorithm").Int(),
		sealedKeyObjx.Get("unlock_key_derivation_algorithm").Int(),
		sealedKeyObjx.Get("unlock_key_iterations").Int(),
	}, nil
}

func getLocalEncryptorDataKey(db *sql.DB, key []byte) ([]byte, error) {
	var blob []byte
	err := db.QueryRow("SELECT value FROM meta WHERE key = 'local_encryptor_data'").Scan(&blob)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}

	ind := bytes.Index(blob, []byte("v10"))

	if ind == -1 {
		return nil, errors.New("main: couldn't find encrypted key from local_encryptor_data")
	}

	encryptedKey, _ := bytes.CutPrefix(blob[ind:], []byte("v10"))

	if len(encryptedKey) < 96 {
		return nil, errors.New("main: invalid encrypted key from local_encryptor_data")
	}

	encryptedKey = encryptedKey[:96]

	decryptedKey, err := decryptAesGcm256(encryptedKey[12:], key, encryptedKey[:12], nil)
	if err != nil {
		return nil, err
	}

	var found bool
	decryptedKey, found = bytes.CutPrefix(decryptedKey, yandexSignature)
	if !found {
		return nil, errInvalidYandexSignature
	}
	if len(decryptedKey) < 32 {
		return nil, errors.New("main: invalid decrypted key from local_encryptor_data")
	}

	return decryptedKey[:32], nil
}

func decryptKeyRsaOaep(passwrod, salt []byte, iterations int, encryptedPrivateKey, encryptedEncryptionKey []byte) ([]byte, error) {
	derivedKey := pbkdf2.Key(passwrod, salt, iterations, 32, sha256.New)

	decryptedPrivateKey, err := decryptAesGcm256(encryptedPrivateKey[12:], derivedKey, encryptedPrivateKey[:12], salt)

	if err != nil {
		return nil, &invalidMasterPasswordTypeError{message: "incorrect master password"}
	}

	if len(decryptedPrivateKey) < 5 {
		return nil, errors.New("main: invalid rsa oaep key")
	}
	decryptedPrivateKey = decryptedPrivateKey[5:]

	privateKey, err := x509.ParsePKCS8PrivateKey(decryptedPrivateKey)
	if err != nil {
		return nil, err
	}

	rsaPrivateKey := privateKey.(*rsa.PrivateKey)

	decrypted, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, rsaPrivateKey, encryptedEncryptionKey, nil)
	if err != nil {
		return nil, err
	}

	decryptKey, found := bytes.CutPrefix(decrypted, yandexSignature)
	if !found {
		return nil, errInvalidYandexSignature
	}

	return decryptKey, nil
}
func (y *yandexDecrypt) PrintCredentials() error {
	// Make sure the Results folder exists
	if _, err := os.Stat("Results"); os.IsNotExist(err) {
		if err := os.Mkdir("Results", 0755); err != nil {
			return fmt.Errorf("failed to create Results directory: %w", err)
		}
	}

	var credentials []string

	for _, profileName := range y.profiles {
		profilePath := filepath.Join(y.path, profileName)
		loginsPath := filepath.Join(profilePath, "Ya Passman Data")

		db, err := sql.Open("sqlite3", loginsPath)
		if err != nil {
			continue
		}
		defer db.Close()

		credentials = append(credentials, fmt.Sprintf("Found logins database: %s", loginsPath))

		sealedKey, err := getSealedKey(db)
		if err != nil {
			continue
		}

		var decryptKey []byte
		masterPassword := false
		if sealedKey != nil {
			masterPassword = true
			if len(sealedKey.encryptedPrivateKey) < 12 {
				continue
			}

			for {
				var password string
				fmt.Print("Enter master password: ")
				fmt.Scan(&password)

				decryptKey, err = decryptKeyRsaOaep([]byte(password), sealedKey.unlockKeySalt, sealedKey.unlockKeyIterations, sealedKey.encryptedPrivateKey, sealedKey.encryptedEncryptionKey)
				imperr := &invalidMasterPasswordTypeError{}
				if errors.As(err, &imperr) {
					fmt.Println("Incorrect master password")
					continue
				}
				if err != nil {
					fmt.Println(err)
					break
				}

				fmt.Println("Correct master password")
				break
			}
		} else {
			decryptKey, err = getLocalEncryptorDataKey(db, y.key)
			if err != nil {
				continue
			}
		}

		if len(decryptKey) == 0 {
			credentials = append(credentials, "Failed to decrypt key to decrypt encrypted data")
			continue
		}

		rows, err := db.Query("SELECT origin_url, username_element, username_value, password_element, password_value, signon_realm FROM logins")
		if err != nil {
			continue
		}
		defer rows.Close()

		for rows.Next() {
			var originUrl, usernameElement, usernameValue, passwordElement, signonRealm string
			var passwordValue []byte

			err = rows.Scan(&originUrl, &usernameElement, &usernameValue, &passwordElement, &passwordValue, &signonRealm)
			if err != nil {
				continue
			}

			strToHash := originUrl + "\x00" + usernameElement + "\x00" + usernameValue + "\x00" + passwordElement + "\x00" + signonRealm
			hash := sha1.New()
			hash.Write([]byte(strToHash))
			hashResult := hash.Sum(nil)

			if masterPassword {
				hashResult = append(hashResult, sealedKey.keyId...)
				passwordValue, err = base64.StdEncoding.DecodeString(string(passwordValue))
				if err != nil {
					continue
				}
			}

			if len(passwordValue) < 12 {
				continue
			}

			decrypted, err := decryptAesGcm256(passwordValue[12:], decryptKey, passwordValue[:12], hashResult)
			if err != nil {
				continue
			}

			credentials = append(credentials,
				"======================================PASSWORD======================================",
				fmt.Sprintf("Url: %s", originUrl),
				fmt.Sprintf("Login: %s", usernameValue),
				fmt.Sprintf("Password: %s", string(decrypted)),
			)
		}
	}

	// Write all credentials to file at once
	outputFile, err := os.Create("Results/yandexpasswords.txt")
	if err != nil {
		return fmt.Errorf("failed to create output file: %w", err)
	}
	defer outputFile.Close()

	for _, cred := range credentials {
		fmt.Fprintln(outputFile, cred)
	}

	return nil
}
func NewYandexDecrypt(path string) (*yandexDecrypt, error) {
	localStateJson, err := os.ReadFile(filepath.Join(path, "Local State"))
	if err != nil {
		return nil, err
	}
	localStateObjx, err := objx.FromJSON(string(localStateJson))
	if err != nil {
		return nil, err
	}
	var profiles []string
	for _, profileNameAny := range localStateObjx.Get("profile.profiles_order").InterSlice() {
		if profileName, ok := profileNameAny.(string); ok {
			profiles = append(profiles, profileName)
		}
	}

	if len(profiles) == 0 {
		return nil, errors.New("main: there is no profiles")
	}

	key, err := base64.StdEncoding.DecodeString(localStateObjx.Get("os_crypt.encrypted_key").Str())
	if err != nil {
		return nil, err
	}

	var ok bool

	key, ok = bytes.CutPrefix(key, []byte("DPAPI"))
	if !ok {
		return nil, errors.New("main: dpapi prefix does not exist")
	}

	decryptedKey, err := decryptDpapi(key)
	if err != nil {
		return nil, err
	}

	return &yandexDecrypt{
		path,
		decryptedKey,
		profiles,
	}, nil
}

type dataBlob struct {
	cbData uint32
	pbData *byte
}

func decryptAesGcm256(encryptedData, key, iv, additionalData []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCMWithNonceSize(block, len(iv))
	if err != nil {
		return nil, err
	}
	return gcm.Open(nil, iv, encryptedData, additionalData)
}

func newBlob(d []byte) *dataBlob {
	if len(d) == 0 {
		return &dataBlob{}
	}
	return &dataBlob{
		pbData: &d[0],
		cbData: uint32(len(d)),
	}
}

func (b *dataBlob) bytes() []byte {
	d := make([]byte, b.cbData)
	copy(d, (*[1 << 30]byte)(unsafe.Pointer(b.pbData))[:])
	return d
}

func decryptDpapi(ciphertext []byte) ([]byte, error) {
	crypt32 := syscall.NewLazyDLL("crypt32.dll")
	kernel32 := syscall.NewLazyDLL("kernel32.dll")
	unprotectDataProc := crypt32.NewProc("CryptUnprotectData")
	localFreeProc := kernel32.NewProc("LocalFree")

	var outBlob dataBlob
	r, _, err := unprotectDataProc.Call(
		uintptr(unsafe.Pointer(newBlob(ciphertext))),
		0, 0, 0, 0, 0,
		uintptr(unsafe.Pointer(&outBlob)),
	)
	if r == 0 {
		return nil, fmt.Errorf("CryptUnprotectData failed with error %w", err)
	}

	defer localFreeProc.Call(uintptr(unsafe.Pointer(outBlob.pbData)))
	return outBlob.bytes(), nil
}
