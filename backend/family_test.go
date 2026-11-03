package backend

import (
	"bytes"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmd-server/user"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/spf13/viper"
)

type fam struct {
	t   *testing.T
	srv *httptest.Server
}

type person struct {
	name  string
	token string
}

func newFam(t *testing.T) *fam {
	t.Helper()
	uio = user.NewUserRepository(t.TempDir(), 5, 5)
	srv := httptest.NewServer(http.StripPrefix("/api/v2", buildApiV2Mux(viper.New())))
	t.Cleanup(func() {
		srv.Close()
		_ = uio.UB.Close()
	})
	return &fam{t, srv}
}

func (f *fam) do(token, method, path string, body any) (int, []byte) {
	f.t.Helper()
	var rd *bytes.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rd = bytes.NewReader(b)
	} else {
		rd = bytes.NewReader(nil)
	}
	req, _ := http.NewRequest(method, f.srv.URL+"/api/v2"+path, rd)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		f.t.Fatal(err)
	}
	defer resp.Body.Close()
	var buf bytes.Buffer
	_, _ = buf.ReadFrom(resp.Body)
	return resp.StatusCode, buf.Bytes()
}

func (f *fam) register(name string) person {
	f.t.Helper()
	b64 := func(n int) string {
		x := make([]byte, n)
		_, _ = rand.Read(x)
		return base64.StdEncoding.EncodeToString(x)
	}
	code, out := f.do("", "POST", "/account/register", map[string]any{
		"username": name, "salt64": b64(16), "passwordHash64": b64(32),
		"protoVersion": 2, "encMasterKey64": b64(60),
	})
	if code != 200 {
		f.t.Fatalf("register %s: %d %s", name, code, out)
	}
	var r struct {
		AccessToken string `json:"accessToken"`
	}
	_ = json.Unmarshal(out, &r)
	return person{name, r.AccessToken}
}

func newKey(t *testing.T) string {
	t.Helper()
	k, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return base64.StdEncoding.EncodeToString(k.PublicKey().Bytes())
}

func (f *fam) giveIdentity(p person) {
	f.t.Helper()
	enc := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{7}, 90))
	code, out := f.do(p.token, "POST", "/account/identity", map[string]string{
		"publicKey64": newKey(f.t), "encPrivateKey64": enc,
	})
	if code != 200 {
		f.t.Fatalf("identity %s: %d %s", p.name, code, out)
	}
}

func sealed(n byte, millis int64, viewer string) map[string]any {
	ct := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{n}, 120))
	return map[string]any{"viewer": viewer, "unixMillis": millis, "ciphertext64": ct}
}

func (f *fam) put(p person, items ...map[string]any) (int, []byte) {
	return f.do(p.token, "POST", "/family/locations", map[string]any{"items": items})
}

type seen struct {
	Items []struct {
		Owner      string `json:"owner"`
		UnixMillis int64  `json:"unixMillis"`
		Ciphertext string `json:"ciphertext64"`
	} `json:"items"`
}

func (f *fam) seen(p person) seen {
	f.t.Helper()
	code, out := f.do(p.token, "GET", "/family/locations", nil)
	if code != 200 {
		f.t.Fatalf("get locations %s: %d %s", p.name, code, out)
	}
	var s seen
	if err := json.Unmarshal(out, &s); err != nil {
		f.t.Fatal(err)
	}
	return s
}

func TestIdentityFirstOneWins(t *testing.T) {
	f := newFam(t)
	a := f.register("alice")

	if code, _ := f.do(a.token, "GET", "/account/identity", nil); code != 404 {
		t.Fatalf("no identity yet: want 404, got %d", code)
	}
	enc := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{1}, 90))
	first := newKey(t)
	if code, out := f.do(a.token, "POST", "/account/identity",
		map[string]string{"publicKey64": first, "encPrivateKey64": enc}); code != 200 {
		t.Fatalf("set identity: %d %s", code, out)
	}
	// A second device that raced: told no, and handed the winner.
	code, out := f.do(a.token, "POST", "/account/identity",
		map[string]string{"publicKey64": newKey(t), "encPrivateKey64": enc})
	if code != 409 {
		t.Fatalf("second identity: want 409, got %d", code)
	}
	var got identityBody
	_ = json.Unmarshal(out, &got)
	if got.PublicKey != first || got.EncPrivate != enc {
		t.Fatalf("409 did not return the stored identity: %+v", got)
	}
	code, out = f.do(a.token, "GET", "/account/identity", nil)
	_ = json.Unmarshal(out, &got)
	if code != 200 || got.PublicKey != first {
		t.Fatalf("get identity: %d %s", code, out)
	}
}

func TestIdentityRejectsBadKeys(t *testing.T) {
	f := newFam(t)
	a := f.register("alice")
	enc := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{1}, 90))
	bad := []map[string]string{
		{"publicKey64": "not base64!!", "encPrivateKey64": enc},
		{"publicKey64": base64.StdEncoding.EncodeToString(make([]byte, 65)), "encPrivateKey64": enc}, // not on the curve
		{"publicKey64": base64.StdEncoding.EncodeToString(make([]byte, 33)), "encPrivateKey64": enc},
		{"publicKey64": newKey(t), "encPrivateKey64": ""},
		{"publicKey64": newKey(t), "encPrivateKey64": "!!"},
	}
	for i, b := range bad {
		if code, _ := f.do(a.token, "POST", "/account/identity", b); code != 400 {
			t.Errorf("case %d: want 400, got %d", i, code)
		}
	}
}

func TestEndpointsNeedLogin(t *testing.T) {
	f := newFam(t)
	for _, c := range [][2]string{
		{"GET", "/family"}, {"GET", "/family/locations"}, {"POST", "/family/locations"},
		{"POST", "/family/pause"}, {"GET", "/account/identity"}, {"POST", "/account/identity"},
	} {
		if code, _ := f.do("", c[0], c[1], nil); code != 400 {
			t.Errorf("%s %s without a token: got %d", c[0], c[1], code)
		}
		if code, _ := f.do("nonsense", c[0], c[1], nil); code != 401 {
			t.Errorf("%s %s with a bad token: got %d", c[0], c[1], code)
		}
	}
}

func TestEveryoneSeesEveryone(t *testing.T) {
	f := newFam(t)
	a, b, c := f.register("alice"), f.register("bob"), f.register("carol")
	f.giveIdentity(a)
	f.giveIdentity(b) // carol has no key yet

	code, out := f.do(a.token, "GET", "/family", nil)
	if code != 200 {
		t.Fatalf("%d %s", code, out)
	}
	var fr familyResponse
	_ = json.Unmarshal(out, &fr)
	if fr.Me.Username != "alice" || fr.Me.Paused {
		t.Errorf("me: %+v", fr.Me)
	}
	if len(fr.People) != 2 || fr.People[0].Username != "bob" || fr.People[1].Username != "carol" {
		t.Fatalf("people: %+v", fr.People)
	}
	if fr.People[0].PublicKey == "" || fr.People[1].PublicKey != "" {
		t.Errorf("keys: bob should have one, carol not: %+v", fr.People)
	}
	_ = c
}

func TestSealedCopyIsPerViewer(t *testing.T) {
	f := newFam(t)
	a, b, c := f.register("alice"), f.register("bob"), f.register("carol")
	for _, p := range []person{a, b, c} {
		f.giveIdentity(p)
	}
	now := time.Now().UnixMilli()

	code, out := f.put(a, sealed(1, now, "bob"), sealed(2, now, "carol"), sealed(3, now, "alice"), sealed(4, now, "nobody"))
	if code != 200 || !strings.Contains(string(out), `"stored":2`) {
		t.Fatalf("put: %d %s (self and unknown viewers must be skipped)", code, out)
	}

	sb, sc, sa := f.seen(b), f.seen(c), f.seen(a)
	if len(sb.Items) != 1 || sb.Items[0].Owner != "alice" {
		t.Fatalf("bob sees %+v", sb)
	}
	if len(sc.Items) != 1 || sc.Items[0].Owner != "alice" {
		t.Fatalf("carol sees %+v", sc)
	}
	if sb.Items[0].Ciphertext == sc.Items[0].Ciphertext {
		t.Error("bob and carol were given the same ciphertext; each viewer gets their own")
	}
	if len(sa.Items) != 0 {
		t.Errorf("alice sees her own copy back: %+v", sa)
	}
}

func TestOnlyTheLastKnownPositionIsKept(t *testing.T) {
	f := newFam(t)
	a, b := f.register("alice"), f.register("bob")
	f.giveIdentity(a)
	f.giveIdentity(b)
	now := time.Now().UnixMilli()

	f.put(a, sealed(1, now-60000, "bob"))
	f.put(a, sealed(2, now, "bob"))
	// An older one arriving late (a retry, a clock) does not replace the newer.
	f.put(a, sealed(3, now-30000, "bob"))

	s := f.seen(b)
	if len(s.Items) != 1 {
		t.Fatalf("want exactly one (no trail), got %d", len(s.Items))
	}
	want := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{2}, 120))
	if s.Items[0].UnixMillis != now || s.Items[0].Ciphertext != want {
		t.Errorf("did not keep the newest: %+v", s.Items[0])
	}
}

func (f *fam) putTo(p person, audience []string, items ...map[string]any) (int, []byte) {
	return f.do(p.token, "POST", "/family/locations", map[string]any{"items": items, "audience": audience})
}

func TestAudienceWithdrawsAPerson(t *testing.T) {
	f := newFam(t)
	a, b, c := f.register("alice"), f.register("bob"), f.register("carol")
	for _, p := range []person{a, b, c} {
		f.giveIdentity(p)
	}
	now := time.Now().UnixMilli()
	if code, out := f.putTo(a, []string{"bob", "carol"}, sealed(1, now, "bob"), sealed(1, now, "carol")); code != 200 ||
		!strings.Contains(string(out), `"stored":2`) {
		t.Fatalf("put: %d %s", code, out)
	}

	// Carol is unticked: her copy goes on the next upload, and an item for her is refused.
	code, out := f.putTo(a, []string{"bob"}, sealed(2, now+1000, "bob"), sealed(2, now+1000, "carol"))
	if code != 200 || !strings.Contains(string(out), `"stored":1`) {
		t.Fatalf("put: %d %s", code, out)
	}
	if n := len(f.seen(c).Items); n != 0 {
		t.Errorf("carol was taken off the audience but still sees %d", n)
	}
	if s := f.seen(b); len(s.Items) != 1 || s.Items[0].UnixMillis != now+1000 {
		t.Errorf("bob should see the newer place: %+v", s)
	}

	// An empty audience shares with no one.
	if code, _ := f.putTo(a, []string{}); code != 200 {
		t.Fatalf("empty audience: %d", code)
	}
	if n := len(f.seen(b).Items); n != 0 {
		t.Errorf("empty audience left bob %d", n)
	}

	// Without an audience nothing is withdrawn (older clients).
	f.put(a, sealed(3, now+2000, "bob"))
	f.put(a, sealed(3, now+2000, "carol"))
	if len(f.seen(b).Items) != 1 || len(f.seen(c).Items) != 1 {
		t.Error("a put without an audience should not withdraw anyone")
	}

	// Carol's own copies for bob are untouched by alice's audience.
	f.put(c, sealed(4, now, "bob"))
	f.putTo(a, []string{})
	if s := f.seen(b); len(s.Items) != 1 || s.Items[0].Owner != "carol" {
		t.Errorf("alice's audience touched carol's copy: %+v", s)
	}
}

func TestPauseWithdrawsAndBlocks(t *testing.T) {
	f := newFam(t)
	a, b := f.register("alice"), f.register("bob")
	f.giveIdentity(a)
	f.giveIdentity(b)
	now := time.Now().UnixMilli()
	f.put(a, sealed(1, now, "bob"))
	if len(f.seen(b).Items) != 1 {
		t.Fatal("setup")
	}

	if code, out := f.do(a.token, "POST", "/family/pause", map[string]bool{"paused": true}); code != 200 {
		t.Fatalf("pause: %d %s", code, out)
	}
	if n := len(f.seen(b).Items); n != 0 {
		t.Errorf("a paused person's last place is still visible (%d)", n)
	}
	if code, _ := f.put(a, sealed(2, now+1000, "bob")); code != 409 {
		t.Errorf("uploading while paused: want 409, got %d", code)
	}
	// Bob can see that she is paused, rather than guess.
	_, out := f.do(b.token, "GET", "/family", nil)
	var fr familyResponse
	_ = json.Unmarshal(out, &fr)
	if len(fr.People) != 1 || !fr.People[0].Paused {
		t.Errorf("bob should be told alice is paused: %+v", fr.People)
	}
	// And she sees it herself.
	_, out = f.do(a.token, "GET", "/family", nil)
	_ = json.Unmarshal(out, &fr)
	if !fr.Me.Paused {
		t.Error("alice's own state should read paused")
	}

	f.do(a.token, "POST", "/family/pause", map[string]bool{"paused": false})
	if code, _ := f.put(a, sealed(3, now+2000, "bob")); code != 200 {
		t.Errorf("after resuming: want 200, got %d", code)
	}
	if len(f.seen(b).Items) != 1 {
		t.Error("after resuming, the new place should show")
	}
}

func TestPutNeedsAnIdentity(t *testing.T) {
	f := newFam(t)
	a, b := f.register("alice"), f.register("bob")
	f.giveIdentity(b)
	if code, _ := f.put(a, sealed(1, time.Now().UnixMilli(), "bob")); code != 412 {
		t.Errorf("want 412, got %d", code)
	}
}

func TestBadItemsAreSkipped(t *testing.T) {
	f := newFam(t)
	a, b := f.register("alice"), f.register("bob")
	f.giveIdentity(a)
	f.giveIdentity(b)
	now := time.Now().UnixMilli()

	huge := sealed(1, now, "bob")
	huge["ciphertext64"] = base64.StdEncoding.EncodeToString(make([]byte, user.MaxSealedBytes+1))
	notB64 := sealed(1, now, "bob")
	notB64["ciphertext64"] = "***"
	future := sealed(1, now+int64(time.Hour/time.Millisecond), "bob")
	zero := sealed(1, 0, "bob")

	code, out := f.put(a, huge, notB64, future, zero)
	if code != 200 || !strings.Contains(string(out), `"stored":0`) {
		t.Errorf("put: %d %s", code, out)
	}
	if len(f.seen(b).Items) != 0 {
		t.Error("a bad item was stored")
	}
}

func TestTooManyItems(t *testing.T) {
	f := newFam(t)
	a := f.register("alice")
	f.giveIdentity(a)
	items := make([]map[string]any, maxFamilyItems+1)
	for i := range items {
		items[i] = sealed(1, time.Now().UnixMilli(), "bob")
	}
	if code, _ := f.put(a, items...); code != 400 {
		t.Errorf("want 400, got %d", code)
	}
}

func TestDeletingAnAccountTakesItsCopiesAway(t *testing.T) {
	f := newFam(t)
	a, b, c := f.register("alice"), f.register("bob"), f.register("carol")
	for _, p := range []person{a, b, c} {
		f.giveIdentity(p)
	}
	now := time.Now().UnixMilli()
	f.put(a, sealed(1, now, "bob"), sealed(1, now, "carol"))
	f.put(c, sealed(2, now, "bob"))
	if len(f.seen(b).Items) != 2 {
		t.Fatal("setup")
	}

	// A viewer leaves: nothing of theirs remains, and the owner can keep sharing.
	f.do(c.token, "DELETE", "/account", nil)
	s := f.seen(b)
	if len(s.Items) != 1 || s.Items[0].Owner != "alice" {
		t.Errorf("after carol left bob should see only alice: %+v", s)
	}
	if code, _ := f.put(a, sealed(5, now+1000, "bob"), sealed(5, now+1000, "carol")); code != 200 {
		t.Errorf("put after a viewer left: %d", code)
	}

	// An owner leaves: her copies go too.
	f.do(a.token, "DELETE", "/account", nil)
	if n := len(f.seen(b).Items); n != 0 {
		t.Errorf("alice left but bob still sees %d", n)
	}
}

func TestMigrationAddsFamilyToAnOlderDatabase(t *testing.T) {
	// A fresh database runs every migration; the family tables must exist and work with
	// foreign keys on (cascade is covered above).
	f := newFam(t)
	a := f.register("alice")
	if code, _ := f.do(a.token, "GET", "/family", nil); code != 200 {
		t.Fatalf("family on a fresh database: %d", code)
	}
}
