package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base32"
	"fmt"
	"os"
	"path/filepath"
)

func main() {
	asking()
}

func encrypt(plaintext []byte, secretKey []byte) []byte {
	block, err := aes.NewCipher(secretKey)
	if err != nil {
		panic(err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		panic(err)
	}

	nonce := make([]byte, gcm.NonceSize())
	_, err = rand.Read(nonce)
	if err != nil {
		panic(err)
	}

	ciphertext := gcm.Seal(nonce, nonce, plaintext, nil) //nonce+plaintext
	return ciphertext                                    //byte array
}

func decrypt(ciphertext []byte, secretKey []byte) []byte {
	block, err := aes.NewCipher(secretKey)
	if err != nil {
		panic(err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		panic(err)
	}

	nonceSize := gcm.NonceSize()
	nonce, ciphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]

	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		panic(err)
	}
	return plaintext //byte array
}

func asking() {
	fmt.Println("Enter 1 to encrypt, 2 to decrypt, 3 to exit")
	var choice int
	fmt.Scanln(&choice)

	if choice == 1 {
		fmt.Println("Enter the file path to encrypt")
		var path string
		fmt.Scanln(&path)
		data, err := os.ReadFile(path)
		if err != nil {
			fmt.Println("File not found")
			asking()
		}
		fmt.Println("Enter the Secret key")
		var key string
		fmt.Scanln(&key)
		secretKey := genKey(key)
		fmt.Println("Data read successfully")
		encryptedData := encrypt(data, secretKey)
		dir, file := filepath.Split(path)
		encPath := filepath.Join(dir, "enc_"+file)
		err = os.WriteFile(encPath, encryptedData, 0644) //rw-r--r--
		if err != nil {
			fmt.Println("Error writing encrypted file")
			asking()
		}
		fmt.Println("File encrypted successfully as", encPath)
		asking()
	} else if choice == 2 {
		fmt.Println("Enter the file path to decrypt")
		var path string
		fmt.Scanln(&path)
		data, err := os.ReadFile(path)
		if err != nil {
			fmt.Println("File not found")
			asking()
		}
		fmt.Println("Enter the Secret key")
		var key string
		fmt.Scanln(&key)
		secretKey := genKey(key)
		fmt.Println("Data read successfully")
		decryptedData := decrypt(data, secretKey)
		dir, file := filepath.Split(path)
		decPath := filepath.Join(dir, "dec_"+file)
		err = os.WriteFile(decPath, decryptedData, 0644)
		if err != nil {
			fmt.Println("Error writing decrypted file")
			asking()
		}
		fmt.Println("File decrypted successfully as", decPath)
		asking()
	} else if choice == 3 {
		os.Exit(0)
	} else {
		fmt.Println("Invalid choice")
		asking()
	}
}

func genKey(key string) []byte {
	// To understand it better:
	// 1. Using this tool: https://emn178.github.io/online-tools/sha256.html
	//    We encode the input to get the hash
	//    Note: a. Input type UTF-8
	//	    b. Output type Hex
	// 2. Using this tool: https://emn178.github.io/online-tools/base32_encode.html
	//    We encode the hash to get the secret key
	//    Note: a. Input type Hex
	// 3. We take the secret key from the first 32 characters
	// 4. We convert the secret key to a byte array and return it

	hash := sha256.New()
	hash.Write([]byte(key))
	encoded := base32.StdEncoding.EncodeToString(hash.Sum(nil)[:])[:32]
	fmt.Println("Secret key is", string(encoded))
	return []byte(encoded)
}
