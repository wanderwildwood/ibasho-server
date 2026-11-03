package main

// Family sharing for an Overland account (see docs/PLAN-family.md).
//
// The phone that would normally do this is an iPhone running Overland, which knows nothing of
// it, so the shim does what the Android app does: it holds the account's identity key and, after
// each batch, seals the newest point for each person the account shares with. The shim already
// sees these points in the clear (it encrypts them for storage), so this costs nothing in privacy.
//
// Where the key lives: on the server, in the account's identity_enc_private, wrapped with
// AES-256-GCM under an Argon2id key made from the account password -- the same protection the
// account's RSA private key already has. The shim keeps no new secret: it re-derives the wrapping
// key from the password already in its config. The only new file is a small JSON state file
// (default: next to the config, "<config>.family.json") holding the pinned public keys, which are
// not secret.
//
// Byte layout and contexts are the same as web/src/lib/familycrypto.ts and the app's
// FamilyCrypto.kt; a v1 account (this one) differs only in how the wrapping key is made, and the
// web page derives it the same way on a v1 log-in.

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"sort"
	"strings"
	"sync"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/hkdf"
)

const (
	ctxKekIdentity    = "ibasho_v1_kek_identity"
	ctxIdentity       = "ibasho_v1_identity"
	ctxSeal           = "ibasho_v1_seal"
	ctxFamilyPassword = "context:familyIdentity"
	sealVersion       = 1
	pointLen          = 65
	scalarLen         = 32
)

var errBadSeal = errors.New("not a place sealed by that person for this account")

func sha(b []byte) []byte { s := sha256.Sum256(b); return s[:] }

// identityKekV1 is the wrapping key for an account on the v1 protocol: Argon2id of the password,
// with a salt fixed by the username so that every log-in of the account finds the same key.
func identityKekV1(username, password string) []byte {
	salt := sha([]byte(ctxKekIdentity + username))[:argon2SaltLen]
	return argon2.IDKey([]byte(ctxFamilyPassword+password), salt, argon2Time, argon2MemKiB, argon2Threads, argon2HashLen)
}

type identity struct {
	priv *ecdh.PrivateKey
	pub  []byte // 65-byte uncompressed point
	enc  []byte // what the server keeps
}

func gcmOf(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

func generateIdentity(username string, kek []byte) (*identity, error) {
	priv, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	pub := priv.PublicKey().Bytes()
	gcm, err := gcmOf(kek)
	if err != nil {
		return nil, err
	}
	iv := make([]byte, aesIVSize)
	if _, err := rand.Read(iv); err != nil {
		return nil, err
	}
	plain := append(append([]byte{}, priv.Bytes()...), pub...)
	ad := append([]byte(ctxIdentity), sha([]byte(username))...)
	return &identity{priv, pub, gcm.Seal(iv, iv, plain, ad)}, nil
}

func openIdentity(username string, kek, enc []byte) (*identity, error) {
	if len(enc) < aesIVSize+16 {
		return nil, errors.New("identity too short")
	}
	gcm, err := gcmOf(kek)
	if err != nil {
		return nil, err
	}
	ad := append([]byte(ctxIdentity), sha([]byte(username))...)
	plain, err := gcm.Open(nil, enc[:aesIVSize], enc[aesIVSize:], ad)
	if err != nil {
		return nil, errors.New("the identity does not open with this password")
	}
	if len(plain) != scalarLen+pointLen {
		return nil, errors.New("identity has the wrong size")
	}
	priv, err := ecdh.P256().NewPrivateKey(plain[:scalarLen])
	if err != nil {
		return nil, err
	}
	if string(priv.PublicKey().Bytes()) != string(plain[scalarLen:]) {
		return nil, errors.New("identity halves do not match")
	}
	return &identity{priv, plain[scalarLen:], append([]byte{}, enc...)}, nil
}

func sealKey(ikm []byte, owner, viewer string, unixMillis int64) (cipher.AEAD, []byte, error) {
	info := append(append(append(append([]byte(ctxSeal), 0), owner...), 0), viewer...)
	key := make([]byte, 32)
	if _, err := io.ReadFull(hkdf.New(sha256.New, ikm, nil, info), key); err != nil {
		return nil, nil, err
	}
	ad := append(append([]byte(ctxSeal), sha([]byte(owner))...), sha([]byte(viewer))...)
	ad = binary.BigEndian.AppendUint64(ad, uint64(unixMillis))
	gcm, err := gcmOf(key)
	return gcm, ad, err
}

func seal(owner string, ownerPriv *ecdh.PrivateKey, viewer string, viewerPub []byte, unixMillis int64, plaintext []byte) ([]byte, error) {
	vp, err := ecdh.P256().NewPublicKey(viewerPub)
	if err != nil {
		return nil, fmt.Errorf("viewer key: %w", err)
	}
	eph, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	s1, err := eph.ECDH(vp)
	if err != nil {
		return nil, err
	}
	s2, err := ownerPriv.ECDH(vp)
	if err != nil {
		return nil, err
	}
	gcm, ad, err := sealKey(append(s1, s2...), owner, viewer, unixMillis)
	if err != nil {
		return nil, err
	}
	iv := make([]byte, aesIVSize)
	if _, err := rand.Read(iv); err != nil {
		return nil, err
	}
	out := append([]byte{sealVersion}, eph.PublicKey().Bytes()...)
	out = append(out, iv...)
	return gcm.Seal(out, iv, plaintext, ad), nil
}

func openSealed(viewer string, viewerPriv *ecdh.PrivateKey, owner string, ownerPub []byte, unixMillis int64, sealed []byte) ([]byte, error) {
	if len(sealed) < 1+pointLen+aesIVSize+16 || sealed[0] != sealVersion {
		return nil, errBadSeal
	}
	eph, err := ecdh.P256().NewPublicKey(sealed[1 : 1+pointLen])
	if err != nil {
		return nil, errBadSeal
	}
	op, err := ecdh.P256().NewPublicKey(ownerPub)
	if err != nil {
		return nil, errBadSeal
	}
	s1, err := viewerPriv.ECDH(eph)
	if err != nil {
		return nil, errBadSeal
	}
	s2, err := viewerPriv.ECDH(op)
	if err != nil {
		return nil, errBadSeal
	}
	gcm, ad, err := sealKey(append(s1, s2...), owner, viewer, unixMillis)
	if err != nil {
		return nil, err
	}
	iv := sealed[1+pointLen : 1+pointLen+aesIVSize]
	plain, err := gcm.Open(nil, iv, sealed[1+pointLen+aesIVSize:], ad)
	if err != nil {
		return nil, errBadSeal
	}
	return plain, nil
}

// ---------- the plan: who gets a copy (same rules as the app's FamilyLogic) ----------

type familyPerson struct {
	Username  string `json:"username"`
	PublicKey string `json:"publicKey64"`
	Paused    bool   `json:"paused"`
}

type sharePlan struct {
	sealTo     []familyPerson
	audience   []string
	keyChanged []string
}

// planShare: only chosen people with a key; a first-seen key is pinned (pins is updated); a key
// that differs from its pin is not sealed to, and the person stays in the audience so the copy
// sealed to their old key is left alone.
func planShare(me string, people []familyPerson, chosen []string, pins map[string]string) sharePlan {
	want := map[string]bool{}
	for _, c := range chosen {
		want[c] = true
	}
	sort.Slice(people, func(i, j int) bool { return people[i].Username < people[j].Username })
	var p sharePlan
	p.audience = []string{}
	for _, x := range people {
		if x.Username == me || !want[x.Username] {
			continue
		}
		p.audience = append(p.audience, x.Username)
		if x.PublicKey == "" {
			continue
		}
		switch pinned, ok := pins[x.Username]; {
		case !ok:
			pins[x.Username] = x.PublicKey
			p.sealTo = append(p.sealTo, x)
		case pinned == x.PublicKey:
			p.sealTo = append(p.sealTo, x)
		default:
			p.keyChanged = append(p.keyChanged, x.Username)
		}
	}
	return p
}

// ---------- talking to the server's family endpoints ----------

type pinStore struct {
	mu   sync.Mutex
	path string
	Pins map[string]map[string]string `json:"pins"` // account -> person -> key
}

func loadPins(path string) *pinStore {
	ps := &pinStore{path: path, Pins: map[string]map[string]string{}}
	if raw, err := os.ReadFile(path); err == nil {
		_ = json.Unmarshal(raw, ps)
		if ps.Pins == nil {
			ps.Pins = map[string]map[string]string{}
		}
	}
	return ps
}

func (ps *pinStore) forAccount(user string) map[string]string {
	if ps.Pins[user] == nil {
		ps.Pins[user] = map[string]string{}
	}
	return ps.Pins[user]
}

func (ps *pinStore) save() error {
	raw, err := json.MarshalIndent(ps, "", "  ")
	if err != nil {
		return err
	}
	tmp := ps.path + ".tmp"
	if err := os.WriteFile(tmp, raw, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, ps.path)
}

type httpStatusError struct {
	status int
	body   string
}

func (e *httpStatusError) Error() string { return fmt.Sprintf("HTTP %d: %s", e.status, e.body) }

// v2 calls the server's /api/v2 endpoints with the session's access token (a v1 log-in's token is
// accepted there too).
func (c *fmdClient) v2(token, method, path string, body any, out any) error {
	var rd io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return err
		}
		rd = strings.NewReader(string(b))
	}
	req, err := http.NewRequest(method, c.baseURL+"/api/v2"+path, rd)
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return &httpStatusError{resp.StatusCode, strings.TrimSpace(string(raw))}
	}
	if out != nil {
		return json.Unmarshal(raw, out)
	}
	return nil
}

type identityBody struct {
	PublicKey  string `json:"publicKey64"`
	EncPrivate string `json:"encPrivateKey64"`
}

type familyResponse struct {
	Me struct {
		Username string `json:"username"`
		Paused   bool   `json:"paused"`
	} `json:"me"`
	People []familyPerson `json:"people"`
}

type sealedItem struct {
	Viewer     string `json:"viewer,omitempty"`
	Owner      string `json:"owner,omitempty"`
	UnixMillis int64  `json:"unixMillis"`
	Ciphertext string `json:"ciphertext64"`
}

// familyIdentity opens the account's identity from the server, or makes one if it has none.
func (s *session) familyIdentity() (*identity, error) {
	if s.ident != nil {
		return s.ident, nil
	}
	kek := identityKekV1(s.username, s.password)
	var body identityBody
	err := s.client.v2(s.token, http.MethodGet, "/account/identity", nil, &body)
	var he *httpStatusError
	switch {
	case err == nil:
	case errors.As(err, &he) && he.status == http.StatusNotFound:
		made, gerr := generateIdentity(s.username, kek)
		if gerr != nil {
			return nil, gerr
		}
		post := identityBody{base64.StdEncoding.EncodeToString(made.pub), base64.StdEncoding.EncodeToString(made.enc)}
		perr := s.client.v2(s.token, http.MethodPost, "/account/identity", post, nil)
		if perr == nil {
			s.ident = made
			return made, nil
		}
		if !errors.As(perr, &he) || he.status != http.StatusConflict {
			return nil, perr
		}
		// Made elsewhere first (the web page): the first one wins.
		if jerr := json.Unmarshal([]byte(he.body), &body); jerr != nil {
			return nil, jerr
		}
	default:
		return nil, err
	}
	enc, err := base64.StdEncoding.DecodeString(body.EncPrivate)
	if err != nil {
		return nil, err
	}
	id, err := openIdentity(s.username, kek, enc)
	if err != nil {
		return nil, err
	}
	s.ident = id
	return id, nil
}

// withToken runs f with a fresh token, logging in again once if the server says 401.
func (s *session) withToken(f func() error) error {
	for attempt := 0; attempt < 2; attempt++ {
		if err := s.ensure(); err != nil {
			return err
		}
		err := f()
		var he *httpStatusError
		if errors.As(err, &he) && he.status == http.StatusUnauthorized && attempt == 0 {
			s.token, s.pub = "", nil
			continue
		}
		return err
	}
	return fmt.Errorf("giving up after re-login")
}

// shareNewest seals one point (the app's location JSON) for everyone in shareWith and uploads the
// copies, with the audience so anyone no longer listed loses theirs. Returns how many were sealed.
func (s *session) shareNewest(locationJSON string, unixMillis int64, shareWith []string, pins *pinStore) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	sealed := 0
	err := s.withToken(func() error {
		id, err := s.familyIdentity()
		if err != nil {
			return err
		}
		var fam familyResponse
		if err := s.client.v2(s.token, http.MethodGet, "/family", nil, &fam); err != nil {
			return err
		}
		if fam.Me.Paused {
			return nil // turned off on the web page: nothing goes up
		}
		pins.mu.Lock()
		plan := planShare(s.username, fam.People, shareWith, pins.forAccount(s.username))
		saveErr := pins.save()
		pins.mu.Unlock()
		if saveErr != nil {
			log.Printf("%s: could not save pinned keys: %v", s.username, saveErr)
		}
		for _, name := range plan.keyChanged {
			log.Printf("%s: %s has a new key; not sharing with them until it is trusted (remove their pin)", s.username, name)
		}
		items := []sealedItem{}
		for _, p := range plan.sealTo {
			pub, err := base64.StdEncoding.DecodeString(p.PublicKey)
			if err != nil {
				continue
			}
			ct, err := seal(s.username, id.priv, p.Username, pub, unixMillis, []byte(locationJSON))
			if err != nil {
				continue
			}
			items = append(items, sealedItem{Viewer: p.Username, UnixMillis: unixMillis, Ciphertext: base64.StdEncoding.EncodeToString(ct)})
		}
		sealed = len(items)
		return s.client.v2(s.token, http.MethodPost, "/family/locations",
			map[string]any{"items": items, "audience": plan.audience}, nil)
	})
	return sealed, err
}

// seenPlace is one person's last place as this account can open it.
type seenPlace struct {
	Owner string
	Plain string // the location JSON, or "" with Note set
	Note  string
}

// look opens what others shared with this account (the "family" command).
func (s *session) look(pins *pinStore) ([]seenPlace, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []seenPlace
	err := s.withToken(func() error {
		id, err := s.familyIdentity()
		if err != nil {
			return err
		}
		var fam familyResponse
		if err := s.client.v2(s.token, http.MethodGet, "/family", nil, &fam); err != nil {
			return err
		}
		var got struct {
			Items []sealedItem `json:"items"`
		}
		if err := s.client.v2(s.token, http.MethodGet, "/family/locations", nil, &got); err != nil {
			return err
		}
		copies := map[string]sealedItem{}
		for _, it := range got.Items {
			copies[it.Owner] = it
		}
		pins.mu.Lock()
		mine := pins.forAccount(s.username)
		for _, p := range fam.People {
			if _, ok := mine[p.Username]; !ok && p.PublicKey != "" {
				mine[p.Username] = p.PublicKey
			}
		}
		_ = pins.save()
		pins.mu.Unlock()
		sort.Slice(fam.People, func(i, j int) bool { return fam.People[i].Username < fam.People[j].Username })
		for _, p := range fam.People {
			sp := seenPlace{Owner: p.Username}
			c, has := copies[p.Username]
			switch {
			case p.Paused:
				sp.Note = "has turned sharing off"
			case p.PublicKey == "":
				sp.Note = "has not set up sharing"
			case mine[p.Username] != p.PublicKey:
				sp.Note = "key changed; not shown"
			case !has:
				sp.Note = "not sharing with this account"
			default:
				pub, _ := base64.StdEncoding.DecodeString(p.PublicKey)
				ct, _ := base64.StdEncoding.DecodeString(c.Ciphertext)
				plain, err := openSealed(s.username, id.priv, p.Username, pub, c.UnixMillis, ct)
				if err != nil {
					sp.Note = "could not be opened"
				} else {
					sp.Plain = string(plain)
				}
			}
			out = append(out, sp)
		}
		return nil
	})
	return out, err
}
