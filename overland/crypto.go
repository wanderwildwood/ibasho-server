package main

// Everything in this file exists to match what the FMD Android app does, byte
// for byte. If any of it drifts, locations still upload and still look fine on
// the wire -- they just never decrypt again. So it is written against the app's
// CypherUtils.java rather than against a spec, and there is a test that proves
// a round trip.

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"strings"

	"golang.org/x/crypto/argon2"
)

// CypherUtils.java
const (
	argon2Time    = 1
	argon2Threads = 4
	argon2MemKiB  = 131072 // withMemoryAsKB(131072) == 128 MiB
	argon2HashLen = 32
	argon2SaltLen = 16

	aesKeySize = 32 // AES-256
	aesIVSize  = 12

	rsaKeyBits = 3072
)

// Argon2 usages are context-separated; using the wrong prefix produces a hash
// the server will simply reject as a bad password.
const (
	ctxLogin      = "context:loginAuthentication"
	ctxKeyWrap    = "context:asymmetricKeyWrap"
)

// Android's Base64.NO_PADDING|Base64.NO_WRAP, used inside the Argon2 string.
var b64Raw = base64.RawStdEncoding

// hashPasswordForLogin mirrors CypherUtils.hashPasswordForLogin. The result is
// the PHC-style string the server stores and compares against.
func hashPasswordForLogin(password string, salt []byte) string {
	sum := argon2.IDKey([]byte(ctxLogin+password), salt, argon2Time, argon2MemKiB, argon2Threads, argon2HashLen)
	return fmt.Sprintf("$argon2id$v=19$m=%d,t=%d,p=%d$%s$%s",
		argon2MemKiB, argon2Time, argon2Threads,
		b64Raw.EncodeToString(salt), b64Raw.EncodeToString(sum))
}

// decodeB64Loose accepts the line-wrapped base64 that Android's Base64.DEFAULT
// emits, which Go's decoder would otherwise reject.
func decodeB64Loose(s string) ([]byte, error) {
	s = strings.NewReplacer("\n", "", "\r", "", " ", "").Replace(s)
	if b, err := base64.StdEncoding.DecodeString(s); err == nil {
		return b, nil
	}
	return base64.RawStdEncoding.DecodeString(s)
}

// encryptForDevice mirrors CypherUtils.encryptWithKey: a fresh AES-256 session
// key encrypts the message, and RSA-OAEP(SHA-256) wraps the session key. The
// blob is sessionKeyPacket || iv || ciphertext+tag.
//
// Note this is hybrid, not plain RSA, so the message may be any length.
func encryptForDevice(pub *rsa.PublicKey, msg string) (string, error) {
	sessionKey := make([]byte, aesKeySize)
	if _, err := rand.Read(sessionKey); err != nil {
		return "", err
	}
	ivAndCiphertext, err := encryptWithAES([]byte(msg), sessionKey)
	if err != nil {
		return "", err
	}
	// MGF1 uses SHA-256, not SHA-1 -- the WebCrypto API in the browser frontend
	// only supports SHA-256, and it is the other end of this.
	sessionKeyPacket, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, pub, sessionKey, nil)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(append(sessionKeyPacket, ivAndCiphertext...)), nil
}

// encryptWithAES returns iv || ciphertext+tag, matching CypherUtils.encryptWithAes.
func encryptWithAES(plaintext, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCMWithNonceSize(block, aesIVSize)
	if err != nil {
		return nil, err
	}
	iv := make([]byte, aesIVSize)
	if _, err := rand.Read(iv); err != nil {
		return nil, err
	}
	// Seal appends the tag, which is what the Java side expects.
	return gcm.Seal(iv, iv, plaintext, nil), nil
}

// wrapPrivateKey mirrors encryptPrivateKeyWithPassword: PEM the key, encrypt it
// under an Argon2-derived key, and prepend the salt so it can be unwrapped later.
func wrapPrivateKey(priv *rsa.PrivateKey, password string) (string, error) {
	salt := make([]byte, argon2SaltLen)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	aesKey := argon2.IDKey([]byte(ctxKeyWrap+password), salt, argon2Time, argon2MemKiB, argon2Threads, argon2HashLen)

	der, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return "", err
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})

	ciphertext, err := encryptWithAES(pemBytes, aesKey)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(append(salt, ciphertext...)), nil
}

func encodePublicKey(pub *rsa.PublicKey) (string, error) {
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(der), nil
}

func parsePublicKey(b64 string) (*rsa.PublicKey, error) {
	der, err := decodeB64Loose(b64)
	if err != nil {
		return nil, fmt.Errorf("public key is not base64: %w", err)
	}
	key, err := x509.ParsePKIXPublicKey(der)
	if err != nil {
		return nil, fmt.Errorf("public key is not an X.509 SPKI: %w", err)
	}
	pub, ok := key.(*rsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("public key is not RSA")
	}
	return pub, nil
}

// ---- The reverse direction, used only by the `check` command ----
//
// This is what the browser does. It exists here so that a stored point can be
// proved readable without opening a browser: a 200 from the server says the
// bytes arrived, not that they will ever decrypt again.

func unwrapPrivateKey(wrapped string, password string) (*rsa.PrivateKey, error) {
	blob, err := decodeB64Loose(wrapped)
	if err != nil {
		return nil, err
	}
	if len(blob) < argon2SaltLen+aesIVSize {
		return nil, fmt.Errorf("wrapped key is too short")
	}
	salt, rest := blob[:argon2SaltLen], blob[argon2SaltLen:]
	aesKey := argon2.IDKey([]byte(ctxKeyWrap+password), salt, argon2Time, argon2MemKiB, argon2Threads, argon2HashLen)

	pemBytes, err := decryptWithAES(rest, aesKey)
	if err != nil {
		return nil, fmt.Errorf("unwrapping private key (wrong password?): %w", err)
	}
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, fmt.Errorf("unwrapped key is not PEM")
	}
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	priv, ok := key.(*rsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("unwrapped key is not RSA")
	}
	return priv, nil
}

func decryptWithAES(ivAndCiphertext, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCMWithNonceSize(block, aesIVSize)
	if err != nil {
		return nil, err
	}
	if len(ivAndCiphertext) < aesIVSize {
		return nil, fmt.Errorf("ciphertext is too short")
	}
	return gcm.Open(nil, ivAndCiphertext[:aesIVSize], ivAndCiphertext[aesIVSize:], nil)
}

func decryptForDevice(priv *rsa.PrivateKey, encoded string) (string, error) {
	blob, err := decodeB64Loose(encoded)
	if err != nil {
		return "", err
	}
	packetLen := rsaKeyBits / 8
	if len(blob) < packetLen {
		return "", fmt.Errorf("blob is too short to hold a session key")
	}
	sessionKey, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, priv, blob[:packetLen], nil)
	if err != nil {
		return "", fmt.Errorf("unwrapping session key: %w", err)
	}
	plaintext, err := decryptWithAES(blob[packetLen:], sessionKey)
	if err != nil {
		return "", err
	}
	return string(plaintext), nil
}
