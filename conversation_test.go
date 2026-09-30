package scram

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"io"
	"log"
	"testing"
)

func TestConversation(t *testing.T) {
	const user = "jeff"
	const password = "this is a very complicated password 124385%($%#"
	hasher := Hasher(sha256.New)
	iters := 2048
	var salt [32]byte
	_, err := rand.Read(salt[:])
	if err != nil {
		t.Error(err)
		return
	}

	saltedPassword := hasher.SaltedPassword([]byte(password), salt[:], iters)
	clientKey := hasher.ClientKey(saltedPassword)
	storedKey := hasher.StoredKey(clientKey)
	serverKey := hasher.ServerKey(saltedPassword)

	keyInfo := KeyInfo{
		Salt:   salt[:],
		Iters:  iters,
		Hasher: hasher,
	}

	client := &ClientConversation{
		User:   user,
		Lookup: ClientPasswordLookup(password, hasher),
	}

	serverKeys := ServerKeys{
		ServerKey: serverKey,
		StoredKey: storedKey,
		KeyInfo:   keyInfo,
	}
	server := &ServerConversation{
		Lookup: func(u string) (ServerKeys, bool) {
			if u == user {
				return serverKeys, true
			}
			return ServerKeys{}, false
		},
	}

	resp, err := client.Write(nil)
	if err != nil {
		t.Error(err)
		return
	}
	log.Printf("client: %s", resp)
	resp, err = server.Write(resp)
	if err != nil {
		t.Error(err)
		return
	}
	log.Printf("server: %s", resp)
	resp, err = client.Write(resp)
	if err != nil {
		t.Error(err)
		return
	}
	log.Printf("client: %s", resp)
	resp, err = server.Write(resp)
	if err != io.EOF {
		t.Error(err)
		return
	}
	log.Printf("server: %s", resp)
	resp, err = client.Write(resp)
	if err != io.EOF {
		t.Error(err)
		return
	}

	if !bytes.Equal(server.RecoveredClientKey, clientKey) {
		t.Error("expected recovered client key and client key to be equal")
		return
	}
}
