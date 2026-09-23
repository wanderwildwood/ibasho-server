package main

// Receives location batches from the Overland app on iOS and stores them in FMD
// Server, encrypted, as if they had come from an FMD client.
//
// This exists because an iPhone cannot run our app, and shipping a custom iOS
// client would mean an Apple developer account. Overland is on the App Store,
// posts to any URL, queues points while offline, and is configured by tapping a
// single link -- which matters here, because nobody in this house has an iOS
// device to debug on.
//
// What it costs: points arrive in plaintext and are encrypted here, so this
// process sees them. Everything at rest stays encrypted, and only the browser
// holding the password can read it back.

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strings"
	"sync"
	"time"
)

type deviceConfig struct {
	Name     string `json:"name"`      // shown on the status page
	Token    string `json:"token"`     // the bearer token Overland sends
	User     string `json:"fmd_user"`  // FMD Server account
	Password string `json:"fmd_password"`
}

type config struct {
	FmdURL  string         `json:"fmd_url"`
	Listen  string         `json:"listen"`
	Devices []deviceConfig `json:"devices"`
}

func loadConfig(path string) (*config, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var c config
	if err := json.Unmarshal(raw, &c); err != nil {
		return nil, err
	}
	if c.FmdURL == "" {
		return nil, fmt.Errorf("fmd_url is not set")
	}
	if c.Listen == "" {
		c.Listen = ":8099"
	}
	return &c, nil
}

// ---------- Overland's payload ----------

type overlandBatch struct {
	Locations []overlandLocation `json:"locations"`
}

type overlandLocation struct {
	Geometry struct {
		Coordinates []float64 `json:"coordinates"` // GeoJSON order: lon, lat
	} `json:"geometry"`
	Properties struct {
		Timestamp          string   `json:"timestamp"`
		Altitude           *float64 `json:"altitude"`
		Speed              *float64 `json:"speed"`
		Course             *float64 `json:"course"`
		HorizontalAccuracy *float64 `json:"horizontal_accuracy"`
		BatteryLevel       *float64 `json:"battery_level"` // 0..1
		Motion             []string `json:"motion"`
	} `json:"properties"`
}

// toFmdJSON produces exactly the object FMD's own client encrypts, so the web
// frontend can read it without knowing this bridge exists. Key names come from
// FmdLocation.encodeToJson().
func (o overlandLocation) toFmdJSON() (string, error) {
	if len(o.Geometry.Coordinates) < 2 {
		return "", fmt.Errorf("location has no coordinates")
	}
	ts, err := time.Parse("2006-01-02T15:04:05-0700", o.Properties.Timestamp)
	if err != nil {
		// Overland has shipped more than one timestamp format over the years.
		ts, err = time.Parse(time.RFC3339, o.Properties.Timestamp)
		if err != nil {
			return "", fmt.Errorf("unparseable timestamp %q", o.Properties.Timestamp)
		}
	}

	out := map[string]any{
		"lon":  o.Geometry.Coordinates[0],
		"lat":  o.Geometry.Coordinates[1],
		"date": ts.UnixMilli(),
		"time": ts.Format("Mon Jan 02 15:04:05 MST 2006"),
		// Naming the real source rather than pretending to be GPS: when a point
		// looks wrong, this is the line that says which pipe it came down.
		"provider": provider(o.Properties.Motion),
		"bat":      batteryPercent(o.Properties.BatteryLevel),
	}
	if v := o.Properties.HorizontalAccuracy; v != nil {
		out["accuracy"] = *v
	}
	if v := o.Properties.Altitude; v != nil {
		out["altitude"] = *v
	}
	if v := o.Properties.Speed; v != nil && *v >= 0 {
		out["speed"] = *v
	}
	if v := o.Properties.Course; v != nil && *v >= 0 {
		// FMD writes "heading" here. Note the frontend reads "bearing" and so
		// never displays it -- an upstream mismatch, not ours.
		out["heading"] = *v
	}

	b, err := json.Marshal(out)
	return string(b), err
}

func provider(motion []string) string {
	if len(motion) == 0 {
		return "Overland"
	}
	return "Overland (" + strings.Join(motion, ", ") + ")"
}

func batteryPercent(level *float64) int {
	if level == nil || *level < 0 {
		return -1 // unknown, rather than a confident zero
	}
	return int(*level*100 + 0.5)
}

// ---------- the server ----------

type deviceState struct {
	cfg     deviceConfig
	session *session

	mu        sync.Mutex
	lastPoint time.Time
	lastSeen  time.Time
	received  int
	failed    int
	lastError string
}

type shim struct {
	byToken map[string]*deviceState
	order   []*deviceState
}

func newShim(c *config) *shim {
	client := newFmdClient(c.FmdURL)
	s := &shim{byToken: map[string]*deviceState{}}
	for _, d := range c.Devices {
		st := &deviceState{
			cfg:     d,
			session: &session{client: client, username: d.User, password: d.Password},
		}
		s.byToken[d.Token] = st
		s.order = append(s.order, st)
	}
	return s
}

func bearerToken(r *http.Request) string {
	h := r.Header.Get("Authorization")
	if after, ok := strings.CutPrefix(h, "Bearer "); ok {
		return strings.TrimSpace(after)
	}
	return ""
}

func (s *shim) handleOverland(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST only", http.StatusMethodNotAllowed)
		return
	}
	dev, ok := s.byToken[bearerToken(r)]
	if !ok {
		// Deliberately terse: this endpoint is public, and a wrong token should
		// learn nothing about which tokens exist.
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	var batch overlandBatch
	if err := json.NewDecoder(r.Body).Decode(&batch); err != nil {
		http.Error(w, "bad json", http.StatusBadRequest)
		return
	}

	// Oldest first, so the stored history reads in order.
	sort.SliceStable(batch.Locations, func(i, j int) bool {
		return batch.Locations[i].Properties.Timestamp < batch.Locations[j].Properties.Timestamp
	})

	dev.mu.Lock()
	dev.lastSeen = time.Now()
	dev.mu.Unlock()

	var stored, failed int
	var lastErr string
	var newest time.Time
	for _, loc := range batch.Locations {
		payload, err := loc.toFmdJSON()
		if err != nil {
			failed++
			lastErr = err.Error()
			continue
		}
		if err := dev.session.store(payload); err != nil {
			failed++
			lastErr = err.Error()
			continue
		}
		stored++
		if ts, err := time.Parse("2006-01-02T15:04:05-0700", loc.Properties.Timestamp); err == nil && ts.After(newest) {
			newest = ts
		}
	}

	dev.mu.Lock()
	dev.received += stored
	dev.failed += failed
	if !newest.IsZero() {
		dev.lastPoint = newest
	}
	if lastErr != "" {
		dev.lastError = lastErr
	}
	dev.mu.Unlock()

	if failed > 0 {
		log.Printf("%s: stored %d, failed %d: %s", dev.cfg.Name, stored, failed, lastErr)
	} else if stored > 0 {
		log.Printf("%s: stored %d", dev.cfg.Name, stored)
	}

	// Overland deletes its local queue only on this exact response. Returning it
	// when we failed to store would silently lose points, so we don't.
	if failed > 0 && stored == 0 {
		http.Error(w, "upstream store failed", http.StatusBadGateway)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	fmt.Fprint(w, `{"result":"ok"}`)
}

// handleStatus is the whole point of running this rather than posting straight
// at FMD: setup can be confirmed from here instead of from her phone.
func (s *shim) handleStatus(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	if len(s.order) == 0 {
		fmt.Fprintln(w, "No devices configured.")
		return
	}
	for _, d := range s.order {
		d.mu.Lock()
		fmt.Fprintf(w, "%s\n", d.cfg.Name)
		if d.lastPoint.IsZero() {
			fmt.Fprintf(w, "  Nothing received yet.\n")
		} else {
			fmt.Fprintf(w, "  Last point   %s (%s ago)\n", d.lastPoint.Format(time.RFC1123), roughAge(time.Since(d.lastPoint)))
			fmt.Fprintf(w, "  Last contact %s ago\n", roughAge(time.Since(d.lastSeen)))
		}
		fmt.Fprintf(w, "  Stored %d, failed %d\n", d.received, d.failed)
		if d.lastError != "" {
			fmt.Fprintf(w, "  Last error: %s\n", d.lastError)
		}
		d.mu.Unlock()
		fmt.Fprintln(w)
	}
}

func roughAge(d time.Duration) string {
	switch {
	case d < time.Minute:
		return "less than a minute"
	case d < time.Hour:
		return fmt.Sprintf("%d min", int(d.Minutes()))
	case d < 24*time.Hour:
		return fmt.Sprintf("%.1f hours", d.Hours())
	default:
		return fmt.Sprintf("%.1f days", d.Hours()/24)
	}
}

// ---------- entry points ----------

func main() {
	log.SetFlags(log.LstdFlags)
	if len(os.Args) < 2 {
		usage()
	}
	switch os.Args[1] {
	case "serve":
		cmdServe(os.Args[2:])
	case "register":
		cmdRegister(os.Args[2:])
	case "check":
		cmdCheck(os.Args[2:])
	case "delete":
		cmdDelete(os.Args[2:])
	default:
		usage()
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, `Usage:
  fmd-overland serve    -config <path>
  fmd-overland register -fmd-url <url> -user <name> -password <pw> -registration-token <tok> [-endpoint <url>]
  fmd-overland check    -fmd-url <url> -user <name> -password <pw>
  fmd-overland delete   -fmd-url <url> -user <name> -password <pw>`)
	os.Exit(2)
}

func cmdServe(args []string) {
	fs := flag.NewFlagSet("serve", flag.ExitOnError)
	path := fs.String("config", "/etc/fmd-overland/config.json", "Path to the config file")
	fs.Parse(args)

	c, err := loadConfig(*path)
	if err != nil {
		log.Fatalf("config: %v", err)
	}
	s := newShim(c)

	mux := http.NewServeMux()
	mux.HandleFunc("/overland", s.handleOverland)
	mux.HandleFunc("/status", s.handleStatus)

	log.Printf("listening on %s, forwarding to %s, %d device(s)", c.Listen, c.FmdURL, len(c.Devices))
	srv := &http.Server{
		Addr:         c.Listen,
		Handler:      mux,
		ReadTimeout:  60 * time.Second,
		WriteTimeout: 120 * time.Second,
	}
	log.Fatal(srv.ListenAndServe())
}

func cmdRegister(args []string) {
	fs := flag.NewFlagSet("register", flag.ExitOnError)
	fmdURL := fs.String("fmd-url", "http://127.0.0.1:8098", "FMD Server base URL")
	user := fs.String("user", "", "Requested username")
	password := fs.String("password", "", "Account password")
	regToken := fs.String("registration-token", "", "Server registration token")
	endpoint := fs.String("endpoint", "", "Public URL of this shim's /overland endpoint, for the setup link")
	fs.Parse(args)

	if *user == "" || *password == "" {
		log.Fatal("-user and -password are required")
	}

	client := newFmdClient(*fmdURL)
	username, err := client.register(*user, *password, *regToken)
	if err != nil {
		log.Fatalf("registration failed: %v", err)
	}

	token := randomToken()

	fmt.Printf("Registered account: %s\n\n", username)
	fmt.Printf("Add this to the shim config's \"devices\" list:\n\n")
	block, _ := json.MarshalIndent(deviceConfig{
		Name: username, Token: token, User: username, Password: *password,
	}, "    ", "  ")
	fmt.Printf("    %s\n\n", block)

	if *endpoint != "" {
		setup := fmt.Sprintf("overland://setup?url=%s&token=%s&device_id=%s",
			url.QueryEscape(*endpoint), url.QueryEscape(token), url.QueryEscape(username))
		fmt.Printf("Tapping this link on the phone configures Overland in one step:\n\n  %s\n\n", setup)
	}
	fmt.Printf("Keep the password: it is the only thing that can decrypt this device's locations.\n")
}

// cmdCheck reads the most recent stored point back and decrypts it, the way the
// browser will. This is the only evidence that matters: the upload returning
// 200 says the bytes arrived, not that they are still readable.
func cmdCheck(args []string) {
	fs := flag.NewFlagSet("check", flag.ExitOnError)
	fmdURL := fs.String("fmd-url", "http://127.0.0.1:8098", "FMD Server base URL")
	user := fs.String("user", "", "Account username")
	password := fs.String("password", "", "Account password")
	fs.Parse(args)

	if *user == "" || *password == "" {
		log.Fatal("-user and -password are required")
	}

	client := newFmdClient(*fmdURL)
	token, err := client.login(*user, *password, 300)
	if err != nil {
		log.Fatalf("login: %v", err)
	}
	wrapped, err := client.privateKey(token)
	if err != nil {
		log.Fatalf("fetching private key: %v", err)
	}
	priv, err := unwrapPrivateKey(wrapped, *password)
	if err != nil {
		log.Fatalf("unwrapping private key: %v", err)
	}
	encrypted, err := client.location(token, -1)
	if err != nil {
		log.Fatalf("fetching location: %v", err)
	}
	plaintext, err := decryptForDevice(priv, encrypted)
	if err != nil {
		log.Fatalf("decrypting location: %v", err)
	}
	fmt.Println(plaintext)
}

// cmdDelete removes an account and all of its stored locations.
func cmdDelete(args []string) {
	fs := flag.NewFlagSet("delete", flag.ExitOnError)
	fmdURL := fs.String("fmd-url", "http://127.0.0.1:8098", "FMD Server base URL")
	user := fs.String("user", "", "Account username")
	password := fs.String("password", "", "Account password")
	fs.Parse(args)

	if *user == "" || *password == "" {
		log.Fatal("-user and -password are required")
	}
	client := newFmdClient(*fmdURL)
	token, err := client.login(*user, *password, 300)
	if err != nil {
		log.Fatalf("login: %v", err)
	}
	if err := client.deleteDevice(token); err != nil {
		log.Fatalf("delete: %v", err)
	}
	fmt.Printf("Deleted account %s and everything it stored.\n", *user)
}
