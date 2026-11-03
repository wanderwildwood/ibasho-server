package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"golang.org/x/crypto/hkdf"
)

func b64(b []byte) string { return base64.StdEncoding.EncodeToString(b) }
func unb64(t *testing.T, s string) []byte {
	t.Helper()
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// The v2 wrapping key, as the app and the web page make it from the account's master key.
func kekV2(username string, master []byte) []byte {
	key := make([]byte, 32)
	info := append([]byte(ctxKekIdentity), sha([]byte(username))...)
	_, _ = io.ReadFull(hkdf.New(sha256.New, master, nil, info), key)
	return key
}

type vector struct {
	Username      string `json:"username"`
	MasterKey64   string `json:"masterKey64"`
	Password      string `json:"password"`
	EncPrivate64  string `json:"encPrivate64"`
	PublicKey64   string `json:"publicKey64"`
	Owner         string `json:"owner"`
	OwnerPublic64 string `json:"ownerPublic64"`
	UnixMillis    int64  `json:"unixMillis"`
	Sealed64      string `json:"sealed64"`
	Plaintext     string `json:"plaintext"`
	Note          string `json:"note"`
}

// The web page's vectors and the Android app's must open here, byte for byte.
func TestOpensWhatTheWebPageAndTheAppSealed(t *testing.T) {
	for _, f := range []string{"family-vectors.json", "family-vectors-kotlin.json"} {
		raw, err := os.ReadFile(filepath.Join("..", "web", "test", f))
		if err != nil {
			t.Fatal(err)
		}
		var v vector
		if err := json.Unmarshal(raw, &v); err != nil {
			t.Fatal(err)
		}
		id, err := openIdentity(v.Username, kekV2(v.Username, unb64(t, v.MasterKey64)), unb64(t, v.EncPrivate64))
		if err != nil {
			t.Fatalf("%s: identity: %v", f, err)
		}
		if b64(id.pub) != v.PublicKey64 {
			t.Fatalf("%s: public key differs", f)
		}
		plain, err := openSealed(v.Username, id.priv, v.Owner, unb64(t, v.OwnerPublic64), v.UnixMillis, unb64(t, v.Sealed64))
		if err != nil || string(plain) != v.Plaintext {
			t.Fatalf("%s: open: %v %q", f, err, plain)
		}
		if _, err := openSealed(v.Username, id.priv, v.Owner, unb64(t, v.OwnerPublic64), v.UnixMillis+1, unb64(t, v.Sealed64)); err == nil {
			t.Fatalf("%s: opened at another time", f)
		}
	}
}

func TestSealOpensForTheViewerOnly(t *testing.T) {
	ada, _ := generateIdentity("ada", bytes.Repeat([]byte{1}, 32))
	tomas, _ := generateIdentity("tomas", bytes.Repeat([]byte{2}, 32))
	carol, _ := generateIdentity("carol", bytes.Repeat([]byte{3}, 32))
	place := []byte(`{"lat":1.5,"lon":2.5}`)
	s, err := seal("ada", ada.priv, "tomas", tomas.pub, 1700000000123, place)
	if err != nil {
		t.Fatal(err)
	}
	if got, err := openSealed("tomas", tomas.priv, "ada", ada.pub, 1700000000123, s); err != nil || !bytes.Equal(got, place) {
		t.Fatalf("open: %v", err)
	}
	bent := append([]byte{}, s...)
	bent[len(bent)-1] ^= 1
	for i, try := range []func() error{
		func() error { _, e := openSealed("carol", carol.priv, "ada", ada.pub, 1700000000123, s); return e },
		func() error { _, e := openSealed("tomas", tomas.priv, "carol", carol.pub, 1700000000123, s); return e },
		func() error { _, e := openSealed("tomas", tomas.priv, "ada", ada.pub, 1700000000124, s); return e },
		func() error { _, e := openSealed("tomas", tomas.priv, "ada", ada.pub, 1700000000123, bent); return e },
		func() error { _, e := openSealed("tomas", tomas.priv, "ada", ada.pub, 1700000000123, s[:40]); return e },
	} {
		if try() == nil {
			t.Errorf("case %d opened", i)
		}
	}
	if _, err := openIdentity("ada", bytes.Repeat([]byte{9}, 32), ada.enc); err == nil {
		t.Error("identity opened with the wrong key")
	}
	if _, err := openIdentity("tomas", bytes.Repeat([]byte{1}, 32), ada.enc); err == nil {
		t.Error("identity opened under another name")
	}
}

func TestPlanShare(t *testing.T) {
	people := []familyPerson{
		{"tomas-reyes", "KEY-T", false}, {"me", "KEY-ME", false},
		{"ada-whitlock", "KEY-A", false}, {"newcomer", "", false},
	}
	pins := map[string]string{}
	p := planShare("me", append([]familyPerson{}, people...), nil, pins)
	if len(p.sealTo) != 0 || len(p.audience) != 0 {
		t.Fatalf("nobody chosen, yet %+v", p)
	}
	p = planShare("me", append([]familyPerson{}, people...), []string{"ada-whitlock", "newcomer", "me"}, pins)
	if len(p.sealTo) != 1 || p.sealTo[0].Username != "ada-whitlock" ||
		!reflect.DeepEqual(p.audience, []string{"ada-whitlock", "newcomer"}) || pins["ada-whitlock"] != "KEY-A" {
		t.Fatalf("plan %+v pins %v", p, pins)
	}
	pins["ada-whitlock"] = "OLD"
	p = planShare("me", append([]familyPerson{}, people...), []string{"ada-whitlock", "tomas-reyes"}, pins)
	if len(p.sealTo) != 1 || p.sealTo[0].Username != "tomas-reyes" ||
		!reflect.DeepEqual(p.keyChanged, []string{"ada-whitlock"}) || pins["ada-whitlock"] != "OLD" {
		t.Fatalf("changed key: %+v", p)
	}
	// "*" is everyone but me, a newcomer included; a changed key still stops sealing.
	p = planShare("me", append([]familyPerson{}, people...), []string{"*"}, pins)
	if !reflect.DeepEqual(p.audience, []string{"ada-whitlock", "newcomer", "tomas-reyes"}) ||
		len(p.sealTo) != 1 || p.sealTo[0].Username != "tomas-reyes" ||
		!reflect.DeepEqual(p.keyChanged, []string{"ada-whitlock"}) {
		t.Fatalf("everyone: %+v", p)
	}
	people = append(people, familyPerson{"later", "KEY-L", false})
	p = planShare("me", append([]familyPerson{}, people...), []string{"*"}, pins)
	if len(p.sealTo) != 2 || p.sealTo[0].Username != "later" || pins["later"] != "KEY-L" {
		t.Fatalf("an account made later: %+v", p)
	}
}

// The v1 wrapping key (this shim's accounts) must match the web page's familyv1.ts. This writes a
// vector the web test opens; it is committed and only rewritten with REGEN_VECTORS=1.
func TestV1IdentityVector(t *testing.T) {
	path := filepath.Join("..", "web", "test", "family-vectors-v1.json")
	if raw, err := os.ReadFile(path); err == nil && os.Getenv("REGEN_VECTORS") == "" {
		var v vector
		_ = json.Unmarshal(raw, &v)
		id, err := openIdentity(v.Username, identityKekV1(v.Username, v.Password), unb64(t, v.EncPrivate64))
		if err != nil || b64(id.pub) != v.PublicKey64 {
			t.Fatalf("committed v1 vector no longer opens: %v", err)
		}
		if _, err := openIdentity(v.Username, identityKekV1(v.Username, v.Password+"x"), unb64(t, v.EncPrivate64)); err == nil {
			t.Fatal("opened with the wrong password")
		}
		return
	}
	v := vector{Username: "overland-test", Password: "made-up-password-for-tests",
		Note: "Made by overland/family_test.go: a v1 account's identity, wrapped under Argon2id of the password."}
	id, err := generateIdentity(v.Username, identityKekV1(v.Username, v.Password))
	if err != nil {
		t.Fatal(err)
	}
	v.EncPrivate64, v.PublicKey64 = b64(id.enc), b64(id.pub)
	raw, _ := json.MarshalIndent(v, "", "  ")
	if err := os.WriteFile(path, append(raw, '\n'), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestPinsSurviveAReload(t *testing.T) {
	path := filepath.Join(t.TempDir(), "c.json.family.json")
	ps := loadPins(path)
	ps.forAccount("overland")["ada"] = "KEY-A"
	if err := ps.save(); err != nil {
		t.Fatal(err)
	}
	if loadPins(path).forAccount("overland")["ada"] != "KEY-A" {
		t.Fatal("pin lost")
	}
	if st, _ := os.Stat(path); st.Mode().Perm() != 0o600 {
		t.Errorf("state file mode %v", st.Mode().Perm())
	}
}
