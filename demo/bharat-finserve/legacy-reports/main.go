// legacy-reports builds monthly regulatory reports and ships them to the archive.
package main

import (
	"crypto/des"
	"crypto/md5"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"fmt"
)

const archiveKeyBits = 1024

func archiveKey() (*rsa.PrivateKey, error) {
	return rsa.GenerateKey(rand.Reader, archiveKeyBits)
}

func reportID(data []byte) string {
	return fmt.Sprintf("%x", md5.Sum(data))
}

func legacyCipher(key []byte) error {
	_, err := des.NewTripleDESCipher(key)
	return err
}

func archiveTLS() *tls.Config {
	return &tls.Config{MinVersion: tls.VersionTLS10}
}

func main() {
	_, _ = archiveKey()
	fmt.Println(reportID([]byte("2026-08")))
}
