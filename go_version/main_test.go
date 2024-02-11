package main

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"testing"
)

func generateHash(password string, digest string) string {
	// Concatenate password and digest
	// Create a SHA-256 hasher
	sha256Hash := sha256.New()

	// Compute SHA-256 hash
	sha256Hash.Write([]byte(password + digest[:16]))
	hash := sha256Hash.Sum(nil)
	// Obtain the hexadecimal representation of the computed SHA-256 hash
	computedSHA256Hex := hex.EncodeToString(hash)
	return computedSHA256Hex
}
func TestHelloEmpty(t *testing.T) {
	// Hexadecimal value
	password := "admin"
	digest := "e8d0656d74838f66a927c8706815f0c9"
	hexValue := "512e4568771fc5a82a5915956eba58293366059308f2882c25df1b78350ed260"
	hash := generateHash(password, digest)
	// Decode hex string to bytes
	fmt.Println("received hash:", hexValue)
	fmt.Println("my hash      :", hash)
}
