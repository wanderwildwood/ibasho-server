package main

// A small client for the FMD Server API, covering only what the shim needs:
// register a device, log in, read a public key, and store a location.

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
)

type fmdClient struct {
	baseURL string
	http    *http.Client
}

func newFmdClient(baseURL string) *fmdClient {
	return &fmdClient{
		baseURL: strings.TrimRight(baseURL, "/"),
		http:    &http.Client{Timeout: 30 * time.Second},
	}
}

type dataPackage struct {
	IDT  string
	Data string
}

type loginRequest struct {
	IDT                    string
	Data                   string // the Argon2 password hash
	SessionDurationSeconds uint64
}

type registrationRequest struct {
	RegistrationToken string
	PrivKey           string
	PubKey            string
	Salt              string
	HashedPassword    string
	RequestedUsername string
}

type registrationResponse struct {
	DeviceId string
}

func (c *fmdClient) do(method, path string, body any, out any) error {
	var buf io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return err
		}
		buf = bytes.NewReader(b)
	}
	req, err := http.NewRequest(method, c.baseURL+path, buf)
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	raw, _ := io.ReadAll(resp.Body)
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return fmt.Errorf("%s %s: %s: %s", method, path, resp.Status, strings.TrimSpace(string(raw)))
	}
	if out != nil {
		return json.Unmarshal(raw, out)
	}
	return nil
}

// register creates a new device account. Her phone runs an App Store app that
// knows nothing about FMD, so nothing else in the system can create it.
func (c *fmdClient) register(username, password, registrationToken string) (string, error) {
	priv, err := rsa.GenerateKey(rand.Reader, rsaKeyBits)
	if err != nil {
		return "", err
	}
	salt := make([]byte, argon2SaltLen)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	wrappedPriv, err := wrapPrivateKey(priv, password)
	if err != nil {
		return "", err
	}
	pubKey, err := encodePublicKey(&priv.PublicKey)
	if err != nil {
		return "", err
	}

	var out registrationResponse
	err = c.do(http.MethodPut, "/api/v1/device", registrationRequest{
		RegistrationToken: registrationToken,
		PrivKey:           wrappedPriv,
		PubKey:            pubKey,
		Salt:              b64Raw.EncodeToString(salt),
		HashedPassword:    hashPasswordForLogin(password, salt),
		RequestedUsername: username,
	}, &out)
	if err != nil {
		return "", err
	}
	return out.DeviceId, nil
}

func (c *fmdClient) salt(username string) ([]byte, error) {
	var out dataPackage
	if err := c.do(http.MethodPut, "/api/v1/salt", dataPackage{IDT: username}, &out); err != nil {
		return nil, err
	}
	return decodeB64Loose(out.Data)
}

func (c *fmdClient) login(username, password string, sessionSeconds uint64) (string, error) {
	salt, err := c.salt(username)
	if err != nil {
		return "", fmt.Errorf("fetching salt: %w", err)
	}
	var out dataPackage
	err = c.do(http.MethodPut, "/api/v1/requestAccess", loginRequest{
		IDT:                    username,
		Data:                   hashPasswordForLogin(password, salt),
		SessionDurationSeconds: sessionSeconds,
	}, &out)
	if err != nil {
		return "", err
	}
	return out.Data, nil
}

func (c *fmdClient) publicKey(accessToken string) (*rsa.PublicKey, error) {
	var out dataPackage
	if err := c.do(http.MethodPut, "/api/v1/pubKey", dataPackage{IDT: accessToken}, &out); err != nil {
		return nil, err
	}
	return parsePublicKey(out.Data)
}

func (c *fmdClient) postLocation(accessToken, encrypted string) error {
	return c.do(http.MethodPost, "/api/v1/location", dataPackage{IDT: accessToken, Data: encrypted}, nil)
}

// session keeps one device's access token and public key, re-logging in when
// the token expires. An expired token comes back as a 401, not as a nice error,
// so the retry is driven by the failure rather than by a clock.
type session struct {
	mu       sync.Mutex
	client   *fmdClient
	username string
	password string

	token string
	pub   *rsa.PublicKey
}

const sessionSeconds = 7 * 24 * 60 * 60

func (s *session) ensure() error {
	if s.token != "" && s.pub != nil {
		return nil
	}
	token, err := s.client.login(s.username, s.password, sessionSeconds)
	if err != nil {
		return fmt.Errorf("login as %q: %w", s.username, err)
	}
	pub, err := s.client.publicKey(token)
	if err != nil {
		return fmt.Errorf("fetching public key for %q: %w", s.username, err)
	}
	s.token, s.pub = token, pub
	return nil
}

// store encrypts and uploads one location, refreshing the session once if the
// server rejects the token.
func (s *session) store(locationJSON string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	for attempt := 0; attempt < 2; attempt++ {
		if err := s.ensure(); err != nil {
			return err
		}
		encrypted, err := encryptForDevice(s.pub, locationJSON)
		if err != nil {
			return err
		}
		err = s.client.postLocation(s.token, encrypted)
		if err == nil {
			return nil
		}
		if strings.Contains(err.Error(), "401") && attempt == 0 {
			// Token expired. Drop it and try once more.
			s.token, s.pub = "", nil
			continue
		}
		return err
	}
	return fmt.Errorf("giving up after re-login")
}

func (c *fmdClient) privateKey(accessToken string) (string, error) {
	var out dataPackage
	if err := c.do(http.MethodPut, "/api/v1/key", dataPackage{IDT: accessToken}, &out); err != nil {
		return "", err
	}
	return out.Data, nil
}

// location fetches one stored point. Index -1 is the most recent.
// The index travels in the body's Data field, not a query parameter, and what
// comes back is the DataPackage that was stored.
func (c *fmdClient) location(accessToken string, index int) (string, error) {
	var out dataPackage
	err := c.do(http.MethodPut, "/api/v1/location",
		dataPackage{IDT: accessToken, Data: strconv.Itoa(index)}, &out)
	if err != nil {
		return "", err
	}
	return out.Data, nil
}

// deleteDevice removes an account and, by the locations table's ON DELETE
// CASCADE, everything it ever stored.
func (c *fmdClient) deleteDevice(accessToken string) error {
	return c.do(http.MethodPost, "/api/v1/device", dataPackage{IDT: accessToken}, nil)
}
