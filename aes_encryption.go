package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"io"
	"io/ioutil"
	"os"
)

func Encrypt(plaintext, passphrase string) (string, error) {
	block, _ := aes.NewCipher([]byte(passphrase))
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}
	textByte := gcm.Seal(
		nonce,
		nonce,
		[]byte(plaintext),
		nil)
	return base64.StdEncoding.EncodeToString(textByte), nil
}

func Decrypt(cipherText, key string) (string, error) {
	keyByte := []byte(key)
	block, err := aes.NewCipher(keyByte)
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	nonceSize := gcm.NonceSize()

	textByte, _ := base64.StdEncoding.DecodeString(cipherText)
	nonce, cipherTextByteClean := textByte[:nonceSize], textByte[nonceSize:]
	plaintextByte, err := gcm.Open(
		nil,
		nonce,
		cipherTextByteClean,
		nil)
	if err != nil {
		return "", err
	}

	return string(plaintextByte), nil
}

func EncryptFile(filePath, passPhrase string) (string, error) {
	content, err := ioutil.ReadFile(filePath)
	if err != nil {
		return "", err
	}

	return Encrypt(string(content), passPhrase)
}

func DecryptFile(chiperText, passPhrase, output string) error {
	text, err := Decrypt(chiperText, passPhrase)
	if err != nil {
		return err
	}

	return ioutil.WriteFile(output, []byte(text), os.FileMode(777))
}
