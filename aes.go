package encrypt

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"
	"io"
)

const (
	byteSize = 8
)

func generateAESKey(bits int) (string, error) {
	if err := validateAESBits(bits); err != nil {
		return "", err
	}
	out := make([]byte, bits/byteSize)
	if _, err := rand.Read(out); err != nil {
		return "", err
	}
	return encodeToString(out), nil
}

type aesTransformer struct {
	block cipher.Block
}

func newAESTransformer(key string) (*aesTransformer, error) {
	block, err := getAESBlock(key)
	if err != nil {
		return nil, err
	}
	return &aesTransformer{block}, nil
}

func (a *aesTransformer) Encrypt(value []byte) ([]byte, error) {
	out := make([]byte, aes.BlockSize+len(value))
	iv := out[:aes.BlockSize]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return nil, err
	}
	cipher.NewCFBEncrypter(a.block, iv).XORKeyStream(out[aes.BlockSize:], value)
	return []byte(encodeToString(out)), nil
}

func (a *aesTransformer) Decrypt(value []byte) ([]byte, error) {
	decodedValueObj, err := decodeString(string(value))
	if err != nil {
		return nil, err
	}
	decodedValue := []byte(decodedValueObj)
	if len(decodedValue) < aes.BlockSize {
		return nil, fmt.Errorf("value too short for AES, expected at least %d, got %d", aes.BlockSize, len(decodedValue))
	}
	out := make([]byte, len(decodedValue)-aes.BlockSize)
	cipher.NewCFBDecrypter(a.block, decodedValue[:aes.BlockSize]).XORKeyStream(out, decodedValue[aes.BlockSize:])
	return out, nil
}

func getAESBlock(key string) (cipher.Block, error) {
	decodedKey, err := decodeString(key)
	if err != nil {
		return nil, err
	}
	if err := validateAESBits(len(decodedKey) * byteSize); err != nil {
		return nil, err
	}
	return aes.NewCipher(decodedKey)
}

func validateAESBits(bits int) error {
	switch bits {
	case AES128Bits:
		return nil
	case AES192Bits:
		return nil
	case AES256Bits:
		return nil
	default:
		return fmt.Errorf("invalid key length: %d", bits)
	}
}
