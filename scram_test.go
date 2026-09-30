package scram

import (
	"crypto/sha1"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/gfx-labs/scram/message"
)

// withNonces makes newNonce return the given values in order.
func withNonces(t *testing.T, nonces ...string) {
	t.Helper()
	old := newNonce
	t.Cleanup(func() { newNonce = old })
	newNonce = func() string {
		n := nonces[0]
		nonces = nonces[1:]
		return n
	}
}

func mustB64(s string) []byte {
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return b
}

func TestRFCVectors(t *testing.T) {
	cases := []struct {
		name                 string
		hasher               Hasher
		clientNonce, srvPart string
		salt                 string
		want                 [4]string
	}{
		{
			name: "RFC5802 SCRAM-SHA-1", hasher: sha1.New,
			clientNonce: "fyko+d2lbbFgONRv9qkxdawL", srvPart: "3rfcNHYJY1ZVvWVs7j", salt: "QSXCR+Q6sek8bf92",
			want: [4]string{
				"n,,n=user,r=fyko+d2lbbFgONRv9qkxdawL",
				"r=fyko+d2lbbFgONRv9qkxdawL3rfcNHYJY1ZVvWVs7j,s=QSXCR+Q6sek8bf92,i=4096",
				"c=biws,r=fyko+d2lbbFgONRv9qkxdawL3rfcNHYJY1ZVvWVs7j,p=v0X8v3Bz2T0CJGbJQyF0X+HI4Ts=",
				"v=rmF9pqV8S7suAoZWja4dJRkFsKQ=",
			},
		},
		{
			name: "RFC7677 SCRAM-SHA-256", hasher: sha256.New,
			clientNonce: "rOprNGfwEbeRWgbNEkqO", srvPart: "%hvYDpWUa2RaTCAfuxFIlj)hNlF$k0", salt: "W22ZaJ0SNY7soEsUEjb6gQ==",
			want: [4]string{
				"n,,n=user,r=rOprNGfwEbeRWgbNEkqO",
				"r=rOprNGfwEbeRWgbNEkqO%hvYDpWUa2RaTCAfuxFIlj)hNlF$k0,s=W22ZaJ0SNY7soEsUEjb6gQ==,i=4096",
				"c=biws,r=rOprNGfwEbeRWgbNEkqO%hvYDpWUa2RaTCAfuxFIlj)hNlF$k0,p=dHzbZapWIk4jUhN+Ute9ytag9zjfMHgsqmmiz7AndVQ=",
				"v=6rriTRBi23WpRR/wtup+mMhUZUn/dB5nLTJRsjl95G4=",
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			withNonces(t, tc.clientNonce, tc.srvPart)
			info := KeyInfo{Salt: mustB64(tc.salt), Iters: 4096, Hasher: tc.hasher}
			sk, err := DeriveServerKeys("pencil", info)
			if err != nil {
				t.Fatal(err)
			}
			srv := NewServerConversation(&ServerConfig{Lookup: staticLookup("user", sk)})
			cli := NewClientConversation(ClientConfig{Username: "user", Lookup: ClientPasswordLookup("pencil", tc.hasher)})

			got := [4]string{}
			m, err := cli.Step(nil)
			must(t, err)
			got[0] = string(m)
			m, err = srv.Step(m)
			must(t, err)
			got[1] = string(m)
			m, err = cli.Step(m)
			must(t, err)
			got[2] = string(m)
			m, err = srv.Step(m)
			must(t, err)
			got[3] = string(m)
			if got != tc.want {
				t.Fatalf("got\n%q\nwant\n%q", got, tc.want)
			}
			m, err = cli.Step(m)
			if err != nil || m != nil || !cli.Authenticated() || !srv.Authenticated() {
				t.Fatalf("final: %v %q", err, m)
			}
		})
	}
}

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

func staticLookup(user string, keys ServerKeys) func(string) (ServerKeys, error) {
	return func(u string) (ServerKeys, error) {
		if u == user {
			return keys, nil
		}
		return ServerKeys{}, ErrUnknownUser
	}
}

var testInfo = KeyInfo{Salt: []byte("0123456789abcdef"), Iters: 4096, Hasher: sha256.New}

func newTestServer(t *testing.T, password string) *ServerConfig {
	t.Helper()
	sk, err := DeriveServerKeys(password, testInfo)
	must(t, err)
	return &ServerConfig{Lookup: staticLookup("jeff", sk)}
}

// exchange runs a full conversation and returns the client and server errors.
func exchange(cfg *ServerConfig, ccfg ClientConfig) (srv *ServerConversation, cerr, serr error) {
	srv = NewServerConversation(cfg)
	cli := NewClientConversation(ccfg)
	m, err := cli.Step(nil)
	if err != nil {
		return srv, err, nil
	}
	for !cli.Done() && !srv.Done() {
		if m, serr = srv.Step(m); serr != nil && m == nil {
			return srv, nil, serr
		}
		if m, cerr = cli.Step(m); cerr != nil {
			return srv, cerr, serr
		}
	}
	return srv, cerr, serr
}

func TestRoundTripAndClientKeys(t *testing.T) {
	cfg := newTestServer(t, "pw")
	srv, cerr, serr := exchange(cfg, ClientConfig{Username: "jeff", Lookup: ClientPasswordLookup("pw", sha256.New)})
	if cerr != nil || serr != nil || !srv.Authenticated() {
		t.Fatal(cerr, serr)
	}
	ck, err := srv.ClientKeys()
	must(t, err)
	want, _ := DeriveClientKeys("pw", testInfo)
	if string(ck.ClientKey) != string(want.ClientKey) || string(ck.ServerKey) != string(want.ServerKey) {
		t.Fatal("recovered keys differ")
	}

	// Intercepted keys log in to another server with the same verifier (pgbouncer use case).
	srv2, cerr, serr := exchange(cfg, ClientConfig{Username: "jeff", Lookup: ClientKeysLookup(ck)})
	if cerr != nil || serr != nil || !srv2.Authenticated() {
		t.Fatal(cerr, serr)
	}
}

// Finding 1.
func TestSASLprepFailureDoesNotCollapse(t *testing.T) {
	for _, pw := range []string{"\x07hunter2", "pass\tword", "שלוםabc1"} {
		a, _ := DeriveClientKeys(pw, testInfo)
		b, _ := DeriveClientKeys("", testInfo)
		if string(a.ClientKey) == string(b.ClientKey) {
			t.Fatalf("%q collides with empty password", pw)
		}
		cfg := newTestServer(t, pw)
		if _, _, serr := exchange(cfg, ClientConfig{Username: "jeff", Lookup: ClientPasswordLookup("", sha256.New)}); !errors.Is(serr, ErrInvalidProof) {
			t.Fatalf("%q: empty password accepted: %v", pw, serr)
		}
		if _, cerr, serr := exchange(cfg, ClientConfig{Username: "jeff", Lookup: ClientPasswordLookup(pw, sha256.New)}); cerr != nil || serr != nil {
			t.Fatalf("%q: correct password rejected: %v %v", pw, cerr, serr)
		}
	}
	if Normalize("I\u00ADX") != "IX" {
		t.Fatal("SASLprep not applied")
	}
}

func clientAfterFirst(t *testing.T, cfg ClientConfig) (*ClientConversation, string) {
	t.Helper()
	cli := NewClientConversation(cfg)
	m, err := cli.Step(nil)
	must(t, err)
	cf, _, _, err := message.ParseClientFirst(string(m))
	must(t, err)
	return cli, cf.Nonce
}

// Finding 2.
func TestClientRejectsBadIterations(t *testing.T) {
	for _, i := range []string{"0", "-1", "1", "4095", "1000001", "2147483647", "9223372036854775807", "99999999999999999999"} {
		cli, n := clientAfterFirst(t, ClientConfig{Lookup: ClientPasswordLookup("pw", sha256.New)})
		start := time.Now()
		_, err := cli.Step([]byte("r=" + n + "x,s=MDEyMzQ1Njc4OWFiY2RlZg==,i=" + i))
		if err == nil || time.Since(start) > time.Second {
			t.Fatalf("i=%s: err=%v took %v", i, err, time.Since(start))
		}
		if !cli.Done() {
			t.Fatal("conversation not terminated")
		}
	}
	cli, n := clientAfterFirst(t, ClientConfig{Lookup: ClientPasswordLookup("pw", sha256.New)})
	if _, err := cli.Step([]byte("r=" + n + "x,s=c2FsdA==,i=4096")); !errors.Is(err, ErrSaltTooShort) {
		t.Fatal("short salt accepted", err)
	}
}

// Finding 3.
func TestServerKeysOnlyAfterSuccess(t *testing.T) {
	cfg := newTestServer(t, "pw")
	srv, _, serr := exchange(cfg, ClientConfig{Username: "jeff", Lookup: ClientPasswordLookup("wrong", sha256.New)})
	if !errors.Is(serr, ErrInvalidProof) || srv.Authenticated() || !srv.Done() {
		t.Fatal(serr)
	}
	if _, err := srv.ClientKeys(); err == nil {
		t.Fatal("keys exposed after failed proof")
	}
	if _, err := srv.Step([]byte("c=biws,r=x,p=AAAA")); !errors.Is(err, ErrConversationFinished) {
		t.Fatal("retry allowed", err)
	}
}

func TestServerFailureSendsErrorMessage(t *testing.T) {
	cfg := newTestServer(t, "pw")
	srv := NewServerConversation(cfg)
	cli := NewClientConversation(ClientConfig{Username: "jeff", Lookup: ClientPasswordLookup("wrong", sha256.New)})
	m, _ := cli.Step(nil)
	m, _ = srv.Step(m)
	m, _ = cli.Step(m)
	m, err := srv.Step(m)
	if string(m) != "e=invalid-proof" || !errors.Is(err, ErrInvalidProof) {
		t.Fatalf("%q %v", m, err)
	}
	if _, err := cli.Step(m); !errors.Is(err, ErrInvalidProof) {
		t.Fatal("client did not surface e=", err)
	}
}

// Finding 4.
func TestChannelBinding(t *testing.T) {
	cb := &ChannelBinding{Type: "tls-server-end-point", Data: []byte("certhash")}
	noCB := newTestServer(t, "pw")
	withCB := newTestServer(t, "pw")
	withCB.ChannelBinding = cb
	required := newTestServer(t, "pw")
	required.ChannelBinding = cb
	required.RequireChannelBinding = true
	lookup := ClientPasswordLookup("pw", sha256.New)

	check := func(name string, cfg *ServerConfig, cc ClientConfig, want error) {
		t.Helper()
		cc.Username, cc.Lookup = "jeff", lookup
		_, cerr, serr := exchange(cfg, cc)
		err := errors.Join(cerr, serr)
		if want == nil && err != nil || want != nil && !errors.Is(err, want) {
			t.Errorf("%s: got %v want %v", name, err, want)
		}
	}
	check("none/none", noCB, ClientConfig{}, nil)
	check("p to server without cb", noCB, ClientConfig{ChannelBinding: cb}, ErrChannelBindingNotSupported)
	check("p matching", withCB, ClientConfig{ChannelBinding: cb}, nil)
	check("p wrong data", withCB, ClientConfig{ChannelBinding: &ChannelBinding{Type: cb.Type, Data: []byte("mitm")}}, ErrChannelBindingsDontMatch)
	check("p wrong type", withCB, ClientConfig{ChannelBinding: &ChannelBinding{Type: "tls-exporter", Data: cb.Data}}, ErrUnsupportedChannelBindingType)
	check("y downgrade", withCB, ClientConfig{ClientSupportsChannelBinding: true}, ErrServerDoesSupportChannelBinding)
	check("y to server without cb", noCB, ClientConfig{ClientSupportsChannelBinding: true}, nil)
	check("n with required", required, ClientConfig{}, ErrChannelBindingsDontMatch)
	check("p with required", required, ClientConfig{ChannelBinding: cb}, nil)

	// c= must match the gs2 header that was sent in client-first.
	srv := NewServerConversation(noCB)
	cli := NewClientConversation(ClientConfig{Username: "jeff", Lookup: lookup})
	m, _ := cli.Step(nil)
	m, _ = srv.Step(m)
	m, _ = cli.Step(m)
	tampered := strings.Replace(string(m), "c=biws", "c="+base64.StdEncoding.EncodeToString([]byte("y,,")), 1)
	if _, err := srv.Step([]byte(tampered)); !errors.Is(err, ErrChannelBindingsDontMatch) {
		t.Fatal("c= mismatch accepted", err)
	}
}

// Finding 5.
func TestClientRejectsForeignNonce(t *testing.T) {
	for _, r := range []string{"totallyunrelated", ""} {
		cli, n := clientAfterFirst(t, ClientConfig{Lookup: ClientPasswordLookup("pw", sha256.New)})
		if r == "" {
			r = n // server added nothing
		}
		if _, err := cli.Step([]byte("r=" + r + ",s=MDEyMzQ1Njc4OWFiY2RlZg==,i=4096")); !errors.Is(err, ErrNonceMismatch) {
			t.Fatalf("%q: %v", r, err)
		}
	}
}

// Finding 6.
func TestClientRejectsMissingServerKey(t *testing.T) {
	good, _ := DeriveClientKeys("pw", testInfo)
	for name, k := range map[string]ClientKeys{
		"nil server key":   {ClientKey: good.ClientKey, KeyInfo: testInfo},
		"zero server key":  {ClientKey: good.ClientKey, ServerKey: make([]byte, 32), KeyInfo: testInfo},
		"short client key": {ClientKey: good.ClientKey[:8], ServerKey: good.ServerKey, KeyInfo: testInfo},
		"nil hasher":       {ClientKey: good.ClientKey, ServerKey: good.ServerKey, KeyInfo: KeyInfo{Salt: testInfo.Salt, Iters: 4096}},
	} {
		_, cerr, _ := exchange(newTestServer(t, "pw"), ClientConfig{Username: "jeff", Lookup: ClientKeysLookup(k)})
		if cerr == nil {
			t.Errorf("%s accepted", name)
		}
		custom := func([]byte, int) (ClientKeys, error) { return k, nil }
		_, cerr, _ = exchange(newTestServer(t, "pw"), ClientConfig{Username: "jeff", Lookup: custom})
		if !errors.Is(cerr, ErrInvalidKeys) {
			t.Errorf("%s accepted from custom lookup: %v", name, cerr)
		}
	}
	// A forged server signature is rejected.
	withNonces(t, "abcdefgh", "ijklmnop")
	cfg := newTestServer(t, "pw")
	srv := NewServerConversation(cfg)
	cli := NewClientConversation(ClientConfig{Username: "jeff", Lookup: ClientKeysLookup(good)})
	m, _ := cli.Step(nil)
	m, _ = srv.Step(m)
	cli.Step(m)
	if _, err := cli.Step([]byte("v=" + base64.StdEncoding.EncodeToString(make([]byte, 32)))); !errors.Is(err, ErrInvalidServerSignature) {
		t.Fatal(err)
	}
}

// Finding 8 and 12.
func TestServerRejectsMalformedClientFirst(t *testing.T) {
	cfg := newTestServer(t, "pw")
	for msg, want := range map[string]error{
		"n,,n=jeff,r=abc,m=ext":   ErrExtensionsNotSupported,
		"n,,m=ext,n=jeff,r=abc":   ErrExtensionsNotSupported,
		"n,,n=jeff,r=abc,r=def":   ErrInvalidEncoding,
		"n,,n=jeff,r=abc,":        ErrInvalidEncoding,
		"n,,n=jeff,r=":            ErrInvalidEncoding,
		"n,,n=jeff,r=a b":         ErrInvalidEncoding,
		"n,,r=abc,n=jeff":         ErrInvalidEncoding,
		"n,,n,=jeff,r=abc":        ErrInvalidEncoding,
		"x,,n=jeff,r=abc":         ErrInvalidEncoding,
		"p=,,n=jeff,r=abc":        ErrInvalidEncoding,
		"n,b=x,n=jeff,r=abc":      ErrInvalidEncoding,
		"n,,n=je=ff,r=abc":        ErrInvalidUsernameEncoding,
		"n,,n=jeff\xff,r=abc":     ErrInvalidEncoding,
		"n,,n=jeff\x00,r=abc":     ErrInvalidEncoding,
		"n,,n=jeff":               ErrInvalidEncoding,
		"n,,":                     ErrInvalidEncoding,
		"":                        ErrInvalidEncoding,
		"n,,n=jeff,r=abc,x=ext":   nil, // optional extension
		strings.Repeat("a", 9000): ErrInvalidEncoding,
	} {
		_, err := NewServerConversation(cfg).Step([]byte(msg))
		if want == nil && err != nil || want != nil && !errors.Is(err, want) {
			t.Errorf("%.40q: got %v want %v", msg, err, want)
		}
	}
}

// Finding 9.
func TestUnknownUserIndistinguishable(t *testing.T) {
	cfg := newTestServer(t, "pw")
	cfg.MockSecret = []byte("secret")
	first := func(user string) string {
		m, err := NewServerConversation(cfg).Step([]byte("n,,n=" + user + ",r=abcdefgh"))
		must(t, err)
		sf, err := message.ParseServerFirst(string(m))
		must(t, err)
		return base64.StdEncoding.EncodeToString(sf.Salt) + "/" + strconv.Itoa(sf.Iters)
	}
	a, b := first("nobody"), first("nobody")
	if a != b {
		t.Fatal("mock salt not stable per user")
	}
	if a == first("other") {
		t.Fatal("mock salt shared between users")
	}
	srv, _, serr := exchange(cfg, ClientConfig{Username: "nobody", Lookup: ClientPasswordLookup("pw", sha256.New)})
	if !errors.Is(serr, ErrInvalidProof) || srv.Authenticated() {
		t.Fatal("unknown user:", serr)
	}

	cfg.Lookup = func(string) (ServerKeys, error) { return ServerKeys{}, errors.New("db down") }
	if _, err := NewServerConversation(cfg).Step([]byte("n,,n=jeff,r=abc")); err == nil || errors.Is(err, ErrUnknownUser) {
		t.Fatal(err)
	}
}

// Finding 10 and 11.
func TestUsernamesAndAuthzid(t *testing.T) {
	for _, u := range []string{"a,b", "a=b", "=2C", "ünï"} {
		sk, _ := DeriveServerKeys("pw", testInfo)
		cfg := &ServerConfig{Lookup: staticLookup(u, sk)}
		srv, cerr, serr := exchange(cfg, ClientConfig{Username: u, Lookup: ClientPasswordLookup("pw", sha256.New)})
		if cerr != nil || serr != nil || srv.Username() != u {
			t.Errorf("%q: %v %v %q", u, cerr, serr, srv.Username())
		}
	}
	for _, u := range []string{"a\x00b", "\xff"} {
		if _, err := NewClientConversation(ClientConfig{Username: u, Lookup: ClientPasswordLookup("pw", sha256.New)}).Step(nil); !errors.Is(err, ErrInvalidUsernameEncoding) {
			t.Errorf("%q: %v", u, err)
		}
	}

	cfg := newTestServer(t, "pw")
	cc := ClientConfig{Username: "jeff", Authzid: "admin", Lookup: ClientPasswordLookup("pw", sha256.New)}
	if _, _, serr := exchange(cfg, cc); !errors.Is(serr, ErrAuthzidNotAllowed) {
		t.Fatal("authzid accepted without Authorize:", serr)
	}
	cfg.Authorize = func(user, authz string) error {
		if user == "jeff" && authz == "admin" {
			return nil
		}
		return errors.New("denied")
	}
	srv, cerr, serr := exchange(cfg, cc)
	if cerr != nil || serr != nil || srv.Authzid() != "admin" {
		t.Fatal(cerr, serr)
	}
	cc.Authzid = "root"
	if _, _, serr := exchange(cfg, cc); serr == nil {
		t.Fatal("denied authzid accepted")
	}

	// Authorize must not run, and Authzid must not be reported, without a valid proof.
	called := false
	cfg.Authorize = func(string, string) error { called = true; return nil }
	cc.Lookup = ClientPasswordLookup("wrong", sha256.New)
	srv, _, serr = exchange(cfg, cc)
	if serr == nil || called || srv.Authzid() != "" {
		t.Fatal("authorize ran before authentication", serr, called, srv.Authzid())
	}
}

func TestConfigValidation(t *testing.T) {
	if _, err := NewServerConversation(&ServerConfig{}).Step([]byte("n,,n=a,r=b")); err == nil {
		t.Fatal("nil Lookup accepted")
	}
	if _, err := NewServerConversation(nil).Step([]byte("n,,n=a,r=b")); err == nil {
		t.Fatal("nil config accepted")
	}
	cfg := newTestServer(t, "pw")
	cfg.RequireChannelBinding = true
	if _, err := NewServerConversation(cfg).Step([]byte("n,,n=jeff,r=b")); err == nil {
		t.Fatal("RequireChannelBinding without ChannelBinding accepted")
	}
	if _, err := NewClientConversation(ClientConfig{}).Step(nil); err == nil {
		t.Fatal("nil client Lookup accepted")
	}
	empty := &ChannelBinding{Type: "tls-server-end-point"}
	cfg = newTestServer(t, "pw")
	cfg.ChannelBinding = empty
	if _, err := NewServerConversation(cfg).Step([]byte("n,,n=jeff,r=b")); err == nil {
		t.Fatal("server channel binding without data accepted")
	}
	cc := ClientConfig{Lookup: ClientPasswordLookup("pw", sha256.New), ChannelBinding: empty}
	if _, err := NewClientConversation(cc).Step(nil); err == nil {
		t.Fatal("client channel binding without data accepted")
	}
}

func TestClientKeysAreCopies(t *testing.T) {
	cfg := newTestServer(t, "pw")
	srv, _, _ := exchange(cfg, ClientConfig{Username: "jeff", Lookup: ClientPasswordLookup("pw", sha256.New)})
	a, err := srv.ClientKeys()
	must(t, err)
	clear(a.ClientKey)
	clear(a.ServerKey)
	clear(a.Salt)
	b, _ := srv.ClientKeys()
	if b.Validate() != nil || string(b.Salt) != string(testInfo.Salt) {
		t.Fatal("ClientKeys shares memory with conversation or stored keys")
	}
}

// Finding 14.
func TestServerRejectsWeakStoredKeys(t *testing.T) {
	weak := KeyInfo{Salt: []byte("0123456789abcdef"), Iters: 1, Hasher: sha256.New}
	sk, _ := DeriveServerKeys("pw", weak)
	cfg := &ServerConfig{Lookup: staticLookup("jeff", sk)}
	if _, err := NewServerConversation(cfg).Step([]byte("n,,n=jeff,r=abc")); !errors.Is(err, ErrIterationsOutOfRange) {
		t.Fatal(err)
	}
	cfg.Lookup = staticLookup("jeff", ServerKeys{KeyInfo: testInfo})
	if _, err := NewServerConversation(cfg).Step([]byte("n,,n=jeff,r=abc")); !errors.Is(err, ErrInvalidKeys) {
		t.Fatal(err)
	}
}

func TestClientStepOrder(t *testing.T) {
	if _, err := NewClientConversation(ClientConfig{}).Step([]byte("x")); err == nil {
		t.Fatal("client accepted input before first message")
	}
}

func TestLibpqEmptyUsername(t *testing.T) {
	sk, _ := DeriveServerKeys("pw", testInfo)
	cfg := &ServerConfig{Lookup: staticLookup("", sk)}
	_, cerr, serr := exchange(cfg, ClientConfig{Lookup: ClientPasswordLookup("pw", sha256.New)})
	if cerr != nil || serr != nil {
		t.Fatal(cerr, serr)
	}
}
