/*
Package encrypt provides simplified utilities to encrypt and decrypt data using standard libraries.
*/
package encrypt

const (
	// AES128Bits is the number of bits in an AES-128 key.
	AES128Bits = 128
	// AES192Bits is the number of bits in an AES-192 key.
	AES192Bits = 192
	// AES256Bits is the number of bits in an AES-256 key.
	AES256Bits = 256
	// RSA2048Bits is the number of bits in a 2048-bit RSA key.
	RSA2048Bits = 2048
)

// Encryptor encrypts data.
type Encryptor interface {
	// Encrypt encrypts the given data. The returned data will be base64 encoded.
	Encrypt([]byte) ([]byte, error)
}

// Decryptor decrypts data.
type Decryptor interface {
	// Decrypt decrypts base64 encoded data.
	Decrypt([]byte) ([]byte, error)
}

// Transformer is both an Encryptor and Decryptor.
type Transformer interface {
	Encryptor
	Decryptor
}

// GenerateAESKey generates a new AES key for the given number of bits.
// The returned key will be base64 encoded.
func GenerateAESKey(bits int) (string, error) {
	return generateAESKey(bits)
}

// NewAESTransformer creates a new AES Transformer with the given base64 encoded key.
func NewAESTransformer(key string) (Transformer, error) {
	return newAESTransformer(key)
}

// GenerateRSAKeys generates a new public and private (in that order of returned values) key.
func GenerateRSAKeys(bits int) (string, string, error) {
	return generateRSAKeys(bits)
}

// NewRSAEncryptor returns a new RSA Encryptor with the given public key.
func NewRSAEncryptor(publicKey string) (Encryptor, error) {
	return newRSAEncryptor(publicKey)
}

// NewRSATransformer returns a new RSA Transformer with the given private key.
func NewRSATransformer(privateKey string) (Transformer, error) {
	return newRSATransformer(privateKey)
}
