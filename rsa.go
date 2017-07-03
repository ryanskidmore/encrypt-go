package encrypt

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha512"
	"crypto/x509"
	"encoding/pem"
	"fmt"
)

const (
	rsaPublicBlockType  = "RSA PUBLIC KEY"
	rsaPrivateBlockType = "RSA PRIVATE KEY"
)

func generateRSAKeys(bits int) (string, string, error) {
	if err := validateRSABits(bits); err != nil {
		return "", "", err
	}
	privateKey, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		return "", "", err
	}
	pubASN1, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	if err != nil {
		return "", "", err
	}
	publicKeyBytes := pem.EncodeToMemory(
		&pem.Block{
			Type:  rsaPublicBlockType,
			Bytes: pubASN1,
		},
	)
	privateKeyBytes := pem.EncodeToMemory(
		&pem.Block{
			Type:  rsaPrivateBlockType,
			Bytes: x509.MarshalPKCS1PrivateKey(privateKey),
		},
	)
	return string(publicKeyBytes), string(privateKeyBytes), nil
}

type rsaEncryptor struct {
	rsaPublicKey *rsa.PublicKey
}

func newRSAEncryptor(publicKey string) (*rsaEncryptor, error) {
	rsaPublicKey, err := getRSAPublicKey(publicKey)
	if err != nil {
		return nil, err
	}
	return &rsaEncryptor{rsaPublicKey}, nil
}

func (e *rsaEncryptor) Encrypt(value []byte) ([]byte, error) {
	encrypted, err := rsa.EncryptOAEP(sha512.New(), rand.Reader, e.rsaPublicKey, value, nil)
	if err != nil {
		return nil, err
	}
	return []byte(EncodeToString(encrypted)), nil
}

type rsaTransformer struct {
	rsaPrivateKey *rsa.PrivateKey
}

func newRSATransformer(privateKey string) (*rsaTransformer, error) {
	rsaPrivateKey, err := getRSAPrivateKey(privateKey)
	if err != nil {
		return nil, err
	}
	return &rsaTransformer{rsaPrivateKey}, nil
}

func (t *rsaTransformer) Encrypt(value []byte) ([]byte, error) {
	encrypted, err := rsa.EncryptOAEP(sha512.New(), rand.Reader, &t.rsaPrivateKey.PublicKey, value, nil)
	if err != nil {
		return nil, err
	}
	return []byte(EncodeToString(encrypted)), nil
}

func (t *rsaTransformer) Decrypt(value []byte) ([]byte, error) {
	decodedValueObj, err := DecodeString(string(value))
	if err != nil {
		return nil, err
	}
	return rsa.DecryptOAEP(sha512.New(), rand.Reader, t.rsaPrivateKey, []byte(decodedValueObj), nil)
}

func getRSAPublicKey(publicKey string) (*rsa.PublicKey, error) {
	block, rest := pem.Decode([]byte(publicKey))
	if rest != nil && len(rest) > 0 {
		return nil, fmt.Errorf("extraneous input: %v", rest)
	}
	if block.Type != rsaPublicBlockType {
		return nil, fmt.Errorf("expected block type of %s, got %s", rsaPublicBlockType, block.Type)
	}
	publicKeyObj, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	return publicKeyObj.(*rsa.PublicKey), nil
}

func getRSAPrivateKey(privateKey string) (*rsa.PrivateKey, error) {
	block, rest := pem.Decode([]byte(privateKey))
	if rest != nil && len(rest) > 0 {
		return nil, fmt.Errorf("extraneous input: %v", rest)
	}
	if block.Type != rsaPrivateBlockType {
		return nil, fmt.Errorf("expected block type of %s, got %s", rsaPrivateBlockType, block.Type)
	}
	return x509.ParsePKCS1PrivateKey(block.Bytes)
}

func validateRSABits(bits int) error {
	switch bits {
	case RSA2048Bits:
		return nil
	case RSA3072Bits:
		return nil
	default:
		return fmt.Errorf("invalid key length: %d", bits)
	}
}
