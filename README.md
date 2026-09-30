# scram

SCRAM (RFC 5802, RFC 7677) client and server for Go.

Written so a proxy can recover a client's keys and use them to log in upstream, like pgbouncer does.

## Server

```go
cfg := &scram.ServerConfig{
	Lookup: func(user string) (scram.ServerKeys, error) {
		keys, ok := db[user]
		if !ok {
			return scram.ServerKeys{}, scram.ErrUnknownUser // runs a mock exchange
		}
		return keys, nil
	},
}
conv := scram.NewServerConversation(cfg)
out, err := conv.Step(clientFirst)  // server-first
out, err = conv.Step(clientFinal)   // server-final; on failure out holds "e=..." and err is set
if conv.Authenticated() {
	keys, _ := conv.ClientKeys() // password-equivalent, usable with ClientKeysLookup
}
```

Create stored keys with `scram.NewKeyInfo(sha256.New, 4096)` and `scram.DeriveServerKeys(password, info)`.

## Client

```go
conv := scram.NewClientConversation(scram.ClientConfig{
	Lookup: scram.ClientPasswordLookup(password, sha256.New), // or scram.ClientKeysLookup(keys)
})
out, err := conv.Step(nil)       // client-first
out, err = conv.Step(serverFirst) // client-final
_, err = conv.Step(serverFinal)   // verifies the server signature
```

## Security notes

- Any error ends a conversation. `ClientKeys` is only available after a valid proof.
- Unknown users get a deterministic fake salt and fail at the proof step. Set `ServerConfig.MockSecret` so fake salts are stable across restarts, and set `MockHasher`/`MockIters` to match real users.
- Channel binding is supported through `ChannelBinding`. Clients that send `y` to a server with channel binding are rejected as a downgrade.
- The client rejects iteration counts outside `[MinIters, MaxIters]` (default 4096 to 1,000,000) and salts shorter than 8 bytes.
- Authzid is rejected unless `ServerConfig.Authorize` is set.
- Passwords that fail SASLprep are used as-is, matching PostgreSQL.
- Conversations are not safe for concurrent use.
