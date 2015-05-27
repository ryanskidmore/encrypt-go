package encrypt

import "encoding/base64"

func encodeToString(value []byte) string {
	return base64.StdEncoding.EncodeToString(value)
}

func decodeString(value string) ([]byte, error) {
	return base64.StdEncoding.DecodeString(value)
}
