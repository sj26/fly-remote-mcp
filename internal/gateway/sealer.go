package gateway

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
)

const sealedTokenPrefix = "fmcp_"

type sealer struct {
	aead cipher.AEAD
}

func newSealer(encodedKey string) (*sealer, error) {
	key, err := base64.RawURLEncoding.DecodeString(encodedKey)
	if err != nil {
		key, err = base64.StdEncoding.DecodeString(encodedKey)
	}
	if err != nil || len(key) != 32 {
		return nil, errors.New("TOKEN_ENCRYPTION_KEY must be a base64-encoded 32-byte key")
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("create token cipher: %w", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("create token AEAD: %w", err)
	}
	return &sealer{aead: aead}, nil
}

func (s *sealer) seal(purpose string, value any) (string, error) {
	plaintext, err := json.Marshal(value)
	if err != nil {
		return "", fmt.Errorf("encode %s token: %w", purpose, err)
	}

	// Keep encrypted state below the open limit and leave room for the other
	// fields in our 32 KiB OAuth forms. Never issue state we cannot receive back.
	if len(sealedTokenPrefix)+base64.RawURLEncoding.EncodedLen(s.aead.NonceSize()+len(plaintext)+s.aead.Overhead()) > 24*1024 {
		return "", errors.New("sealed token is too large")
	}

	nonce := make([]byte, s.aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", fmt.Errorf("create %s token nonce: %w", purpose, err)
	}

	sealed := s.aead.Seal(nonce, nonce, plaintext, []byte("fly-mcp:"+purpose+":v1"))
	return sealedTokenPrefix + base64.RawURLEncoding.EncodeToString(sealed), nil
}

func (s *sealer) open(token, purpose string, dst any) error {
	if !strings.HasPrefix(token, sealedTokenPrefix) {
		return errors.New("invalid sealed token")
	}
	encoded := strings.TrimPrefix(token, sealedTokenPrefix)
	if len(encoded) > 32*1024 {
		return errors.New("sealed token is too large")
	}
	sealed, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil || len(sealed) < s.aead.NonceSize()+s.aead.Overhead() {
		return errors.New("invalid sealed token")
	}

	nonce := sealed[:s.aead.NonceSize()]
	plaintext, err := s.aead.Open(nil, nonce, sealed[s.aead.NonceSize():], []byte("fly-mcp:"+purpose+":v1"))
	if err != nil {
		return errors.New("invalid sealed token")
	}
	if err := json.Unmarshal(plaintext, dst); err != nil {
		return errors.New("invalid sealed token")
	}
	return nil
}
