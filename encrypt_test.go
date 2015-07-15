package encrypt

import (
	"bytes"
	"crypto/rand"
	"fmt"
	"testing"
)

const (
	testAESDataLength = 1 << 10
	testRSADataLength = 1 << 5
)

func TestAES(t *testing.T) {
	key, err := GenerateAESKey(AES256Bits)
	if err != nil {
		t.Fatal(err)
	}
	fmt.Printf("AES key is %s, length %d\n", key, len(key))
	transformer, err := NewAESTransformer(key)
	if err != nil {
		t.Fatal(err)
	}
	testAll(t, transformer, testAESDataLength)
}

func TestRSA(t *testing.T) {
	publicKey, privateKey, err := GenerateRSAKeys(RSA2048Bits)
	if err != nil {
		t.Fatal(err)
	}
	fmt.Printf("RSA public key is %s\nRSA private key is %s\n", publicKey, privateKey)
	transformer, err := NewRSATransformer(privateKey)
	if err != nil {
		t.Fatal(err)
	}
	testAll(t, transformer, testRSADataLength)
}

func testAll(t *testing.T, transformer Transformer, randomDataLength int) {
	testTransform(t, transformer, []byte("hello"))
	testRandom(t, transformer, randomDataLength)
}

func testRandom(t *testing.T, transformer Transformer, dataLength int) {
	expected := make([]byte, dataLength)
	if _, err := rand.Read(expected); err != nil {
		t.Fatal(err)
	}
	testTransform(t, transformer, expected)
}

func testTransform(t *testing.T, transformer Transformer, expected []byte) {
	encrypted, err := transformer.Encrypt(expected)
	if err != nil {
		t.Fatal(err)
	}
	fmt.Printf("encrypted is %s\n", string(encrypted))
	actual, err := transformer.Decrypt(encrypted)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(expected, actual) {
		t.Errorf("expected %v, got %v", expected, actual)
	}
}
