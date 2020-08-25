package main

import (
	"io/ioutil"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
)

var key = "26703200100ada761c68e82e296d208d"

func Test_encryption(t *testing.T) {
	tests := []struct {
		name, plainText, key string
	}{
		{
			name:      "Test #1 success",
			plainText: "bhinneka",
			key:       key,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cipherText, err := Encrypt(tt.plainText, tt.key)
			assert.NoError(t, err)

			plaintext, err := Decrypt(cipherText, tt.key)
			assert.NoError(t, err)

			assert.Equal(t, plaintext, tt.plainText)
		})
	}
}

func TestEncryptFile(t *testing.T) {
	tests := []struct {
		name, file, key, outputFile string
	}{
		{
			name:       "test#1 success",
			file:       "sample_file.txt",
			key:        key,
			outputFile: "output_file.txt",
		},
		{
			name:       "test#2 success image",
			file:       "sample-image.jpg",
			key:        key,
			outputFile: "output-image.jpg",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			os.Remove(tt.outputFile)
			cipherText, err := EncryptFile(tt.file, tt.key)
			assert.NoError(t, err)

			err = DecryptFile(cipherText, tt.key, tt.outputFile)
			assert.NoError(t, err)

			file, _ := ioutil.ReadFile(tt.file)
			output, _ := ioutil.ReadFile(tt.outputFile)

			assert.Equal(t, file, output)
		})
	}
}

var res string

func BenchmarkEncrypt(b *testing.B) {
	var s string
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		s, _ = Encrypt("bhinneka", key)
	}
	res = s
}

func BenchmarkDecrypt(b *testing.B) {
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		cr, _ := Encrypt("bhinneka", key)
		_, _ = Decrypt(cr, key)
	}
}

func BenchmarkFileDecrypt(b *testing.B) {
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		file := "/tmp/output_file.txt"
		os.Remove(file)
		cr, _ := EncryptFile("sample_file.txt", key)
		_ = DecryptFile(cr, key, file)
	}
}
