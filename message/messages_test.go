package message

import (
	"bytes"
	"testing"
)

func TestSaslname(t *testing.T) {
	for _, s := range []string{"", "user", "a,b", "a=b", "=2C,=3D", "ünï"} {
		enc, err := EncodeSaslname(s)
		if err != nil {
			t.Fatal(err)
		}
		dec, err := DecodeSaslname(enc)
		if err != nil || dec != s {
			t.Fatalf("%q -> %q -> %q %v", s, enc, dec, err)
		}
	}
	for _, s := range []string{"a=", "a=2", "a=2c", "a=41", "a,b", "a\x00"} {
		if _, err := DecodeSaslname(s); err == nil {
			t.Errorf("%q accepted", s)
		}
	}
}

func TestParseServerFirst(t *testing.T) {
	good := "r=abc,s=c2FsdA==,i=4096"
	if m, err := ParseServerFirst(good); err != nil || m.Nonce != "abc" || string(m.Salt) != "salt" || m.Iters != 4096 {
		t.Fatal(m, err)
	}
	for _, s := range []string{
		"r,=abc,s=c2FsdA==,i=1", // lax key parsing
		"r=abc,s=c2FsdA,i=1",    // unpadded
		"r=abc,s=c2FsdA=x,i=1",
		"r=abc,s=c2FsdB==,i=1", // non-canonical padding bits
		"r=abc,s=,i=1",
		"r=abc,s=c2FsdA==,i=0",
		"r=abc,s=c2FsdA==,i=-1",
		"r=abc,s=c2FsdA==,i=+5",
		"r=abc,s=c2FsdA==,i= 5",
		"r=abc,s=c2FsdA==,i=99999999999999999999",
		"r=abc,s=c2FsdA==",
		"r=abc,s=c2FsdA==,i=1,m=x",
		"r=abc,s=c2FsdA==,i=1,s=x",
		"m=x,r=abc,s=c2FsdA==,i=1",
	} {
		if _, err := ParseServerFirst(s); err == nil {
			t.Errorf("%q accepted", s)
		}
	}
}

func TestParseClientFinal(t *testing.T) {
	m, wp, err := ParseClientFinal("c=biws,r=abc,x=y,p=AAAA")
	if err != nil || wp != "c=biws,r=abc,x=y" || string(m.ChannelBinding) != "n,," || m.Nonce != "abc" {
		t.Fatal(m, wp, err)
	}
	for _, s := range []string{"c=biws,r=abc", "c=biws,p=AAAA", "c=biws,r=abc,p=", "c=biws,r=abc,p=AAAA,x=y", "c=biws,r=abc,m=x,p=AAAA", "c=,r=abc,p=AAAA"} {
		if _, _, err := ParseClientFinal(s); err == nil {
			t.Errorf("%q accepted", s)
		}
	}
}

func TestServerFinal(t *testing.T) {
	if m, err := ParseServerFinal("e=invalid-proof"); err != nil || m.Err != ErrInvalidProof {
		t.Fatal(m, err)
	}
	for _, s := range []string{"v=", "e=", "x=abc", "v=AAAA,v=AAAA"} {
		if _, err := ParseServerFinal(s); err == nil {
			t.Errorf("%q accepted", s)
		}
	}
	if _, err := (ServerFinal{}).Encode(); err == nil {
		t.Fatal("empty server-final encoded")
	}
}

func TestClientFirstRoundTrip(t *testing.T) {
	in := ClientFirst{GS2: GS2Header{CBFlag: CBUsed, CBName: "tls-exporter", Authzid: "a,b"}, Username: "u=v", Nonce: "xyz"}
	full, bare, err := in.Encode()
	if err != nil || full != "p=tls-exporter,a=a=2Cb,n=u=3Dv,r=xyz" || bare != "n=u=3Dv,r=xyz" {
		t.Fatal(full, bare, err)
	}
	out, gs2, bare2, err := ParseClientFirst(full)
	if err != nil || out != in || gs2 != "p=tls-exporter,a=a=2Cb," || bare2 != bare {
		t.Fatal(out, gs2, bare2, err)
	}
}

func FuzzParseClientFirst(f *testing.F) {
	f.Add("n,,n=user,r=abc")
	f.Add("p=tls-exporter,a=x=2Cy,n=u,r=abc,x=ext")
	f.Fuzz(func(t *testing.T, s string) {
		m, gs2, bare, err := ParseClientFirst(s)
		if err != nil {
			return
		}
		if gs2+bare != s {
			t.Fatalf("gs2+bare != input: %q %q", gs2, bare)
		}
		full, _, err := m.Encode()
		if err != nil {
			t.Fatalf("parsed message does not re-encode: %v", err)
		}
		m2, _, _, err := ParseClientFirst(full)
		if err != nil || m2 != m {
			t.Fatalf("round trip: %v %v", m2, err)
		}
	})
}

func FuzzParseServerFirst(f *testing.F) {
	f.Add("r=abc,s=c2FsdA==,i=4096")
	f.Fuzz(func(t *testing.T, s string) {
		m, err := ParseServerFirst(s)
		if err != nil {
			return
		}
		if m.Iters < 1 || len(m.Salt) == 0 || m.Nonce == "" {
			t.Fatalf("invalid values accepted: %+v", m)
		}
		enc, err := m.Encode()
		if err != nil {
			t.Fatal(err)
		}
		m2, err := ParseServerFirst(enc)
		if err != nil || m2.Nonce != m.Nonce || !bytes.Equal(m2.Salt, m.Salt) || m2.Iters != m.Iters {
			t.Fatal("round trip")
		}
	})
}

func FuzzParseClientFinal(f *testing.F) {
	f.Add("c=biws,r=abc,p=AAAA")
	f.Fuzz(func(t *testing.T, s string) {
		m, wp, err := ParseClientFinal(s)
		if err != nil {
			return
		}
		if len(m.Proof) == 0 || len(m.ChannelBinding) == 0 || len(wp) >= len(s) || s[:len(wp)] != wp {
			t.Fatalf("bad parse: %+v %q", m, wp)
		}
	})
}

func FuzzParseServerFinal(f *testing.F) {
	f.Add("v=AAAA")
	f.Add("e=other-error")
	f.Fuzz(func(t *testing.T, s string) {
		m, err := ParseServerFinal(s)
		if err != nil {
			return
		}
		if (m.Err == "") == (m.Verifier == nil) {
			t.Fatalf("exactly one of v/e must be set: %+v", m)
		}
	})
}
