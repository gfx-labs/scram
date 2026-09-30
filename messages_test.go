package scram

import (
	"crypto/sha1"
	"crypto/sha256"
	"testing"

	"github.com/gfx-labs/scram/message"
)

type MessageTestCase struct {
	User     string
	Password string
	Nonce1   string
	Nonce2   string
	Salt     []byte
	Iters    int
	Channel  []byte
	Hasher   Hasher

	ExpectedClientFirstMessage string
	ExpectedServerFirstMessage string
	ExpectedClientFinalMessage string
	ExpectedServerFinalMessage string
}

var MessageTestCases = [...]MessageTestCase{
	{
		User:     "user",
		Password: "pencil",
		Nonce1:   "fyko+d2lbbFgONRv9qkxdawL",
		Nonce2:   "fyko+d2lbbFgONRv9qkxdawL3rfcNHYJY1ZVvWVs7j",
		Salt:     []byte{0x41, 0x25, 0xc2, 0x47, 0xe4, 0x3a, 0xb1, 0xe9, 0x3c, 0x6d, 0xff, 0x76},
		Iters:    4096,
		Channel:  []byte{0x6e, 0x2c, 0x2c},
		Hasher:   sha1.New,

		ExpectedClientFirstMessage: "n,,n=user,r=fyko+d2lbbFgONRv9qkxdawL",
		ExpectedServerFirstMessage: "r=fyko+d2lbbFgONRv9qkxdawL3rfcNHYJY1ZVvWVs7j,s=QSXCR+Q6sek8bf92,i=4096",
		ExpectedClientFinalMessage: "c=biws,r=fyko+d2lbbFgONRv9qkxdawL3rfcNHYJY1ZVvWVs7j,p=v0X8v3Bz2T0CJGbJQyF0X+HI4Ts=",
		ExpectedServerFinalMessage: "v=rmF9pqV8S7suAoZWja4dJRkFsKQ=",
	},
	{
		User:     "user",
		Password: "pencil",
		Nonce1:   "rOprNGfwEbeRWgbNEkqO",
		Nonce2:   "rOprNGfwEbeRWgbNEkqO%hvYDpWUa2RaTCAfuxFIlj)hNlF$k0",
		Salt:     []byte{0x5b, 0x6d, 0x99, 0x68, 0x9d, 0x12, 0x35, 0x8e, 0xec, 0xa0, 0x4b, 0x14, 0x12, 0x36, 0xfa, 0x81},
		Iters:    4096,
		Channel:  []byte{0x6e, 0x2c, 0x2c},
		Hasher:   sha256.New,

		ExpectedClientFirstMessage: "n,,n=user,r=rOprNGfwEbeRWgbNEkqO",
		ExpectedServerFirstMessage: "r=rOprNGfwEbeRWgbNEkqO%hvYDpWUa2RaTCAfuxFIlj)hNlF$k0,s=W22ZaJ0SNY7soEsUEjb6gQ==,i=4096",
		ExpectedClientFinalMessage: "c=biws,r=rOprNGfwEbeRWgbNEkqO%hvYDpWUa2RaTCAfuxFIlj)hNlF$k0,p=dHzbZapWIk4jUhN+Ute9ytag9zjfMHgsqmmiz7AndVQ=",
		ExpectedServerFinalMessage: "v=6rriTRBi23WpRR/wtup+mMhUZUn/dB5nLTJRsjl95G4=",
	},
}

func TestMessages(t *testing.T) {
	for _, testCase := range MessageTestCases {
		preparedUser := Normalize([]byte(testCase.User))
		clientFirstMessage := message.EncodeClientFirstMessage(
			nil,
			nil,
			preparedUser,
			[]byte(testCase.Nonce1),
		)
		serverFirstMessage := message.EncodeServerFirstMessage(
			[]byte(testCase.Nonce2),
			testCase.Salt,
			testCase.Iters,
		)
		saltedPassword := testCase.Hasher.SaltedPassword([]byte(testCase.Password), testCase.Salt, testCase.Iters)
		clientKey := testCase.Hasher.ClientKey(saltedPassword)
		storedKey := testCase.Hasher.StoredKey(clientKey)
		authMessage := AuthMessage(
			message.EncodeClientFirstMessageWithoutHeader(preparedUser, []byte(testCase.Nonce1)),
			serverFirstMessage,
			message.EncodeClientFinalMessageWithoutProof(testCase.Channel, []byte(testCase.Nonce2)),
		)
		clientSignature := testCase.Hasher.ClientSignature(storedKey, authMessage)
		clientProof := testCase.Hasher.ClientProof(clientKey, clientSignature)
		clientFinalMessage := message.EncodeClientFinalMessage(
			testCase.Channel,
			[]byte(testCase.Nonce2),
			clientProof,
		)
		serverKey := testCase.Hasher.ServerKey(saltedPassword)
		serverSignature := testCase.Hasher.ServerSignature(serverKey, authMessage)
		serverFinalMessage := message.EncodeServerFinalMessage(
			serverSignature,
		)

		if string(clientFirstMessage) != testCase.ExpectedClientFirstMessage {
			t.Errorf(`incorrect client first message! got "%s" but expected "%s"`, clientFirstMessage, testCase.ExpectedClientFirstMessage)
		}
		if string(serverFirstMessage) != testCase.ExpectedServerFirstMessage {
			t.Errorf(`incorrect server first message! got "%s" but expected "%s"`, serverFirstMessage, testCase.ExpectedServerFirstMessage)
		}
		if string(clientFinalMessage) != testCase.ExpectedClientFinalMessage {
			t.Errorf(`incorrect client final message! got "%s" but expected "%s"`, clientFinalMessage, testCase.ExpectedClientFinalMessage)
		}
		if string(serverFinalMessage) != testCase.ExpectedServerFinalMessage {
			t.Errorf(`incorrect server final message! got "%s" but expected "%s"`, serverFinalMessage, testCase.ExpectedServerFinalMessage)
		}
	}
}
