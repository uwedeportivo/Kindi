package kindi

import (
        "bytes"
        "crypto/rand"
        "crypto/rsa"
	"os"
        "testing"
)

func newEnvelope(t *testing.T) (*Envelope, *rsa.PublicKey, *rsa.PrivateKey)  {
        size := 1024
        sender, err := rsa.GenerateKey(rand.Reader, size)
        if err != nil {
		t.Fatalf("failed to generate sender key")
	}
        recipient, err := rsa.GenerateKey(rand.Reader, size)
	if err != nil {
		t.Fatalf("failed to generate recipient key")
	}

        return &Envelope{
        senderEmail:[]byte("foo@gmail.com"),
        senderKey:sender,
        recipientKey:&recipient.PublicKey,
        }, &sender.PublicKey, recipient
}

func TestNewHeader(t *testing.T) {
        envelope, sender, recipient := newEnvelope(t)

        symmetricKey := make([]byte, 32)
        rand.Read(symmetricKey)

        header, err := envelope.newHeader(symmetricKey)
        if err != nil {
		t.Fatalf("failed new header %v", err)
	}
        
        decryptedKey, err := decryptHeader(header, recipient, func(email []byte) (*rsa.PublicKey, os.Error) {
		return sender, nil
	})
        if err != nil {
		t.Fatalf("failed decrypt header %v", err)
	}
        if ! bytes.Equal(symmetricKey, decryptedKey) {
                t.Fatalf("expected symmetric key and decrypted symmetric key not equal")
        }
}

func TestEncrypt(t *testing.T) {
        payload := []byte{0xd9, 0x4a, 0xe0, 0x83, 0x2e, 0x64, 0x45, 0xce,
		0x42, 0x33, 0x1c, 0xb0, 0x6d, 0x53, 0x1a, 0x82, 0xb1,
		0xdb, 0x4b, 0xaa, 0xd3, 0x0f, 0x74, 0x6d, 0xc9, 0x16,
		0xdf, 0x24, 0xd4, 0xe3, 0xc2, 0x45, 0x1f, 0xff, 0x59,
		0xa6, 0x42, 0x3e, 0xb0, 0xe1, 0xd0, 0x2d, 0x4f, 0xe6,
		0x46, 0xcf, 0x69, 0x9d, 0xfd, 0x81, 0x8c, 0x6e, 0x97,
		0xb0, 0x51}
        inbuffer := bytes.NewBuffer(payload)
        outbuffer := bytes.NewBuffer(make([]byte, 0, 1024))

        envelope, sender, recipient := newEnvelope(t)

        err := envelope.Encrypt(outbuffer, inbuffer)
        if err != nil {
		t.Fatalf("failed to encrypt %v", err)
	}

        roundtripbuffer := bytes.NewBuffer(make([]byte, 0, 1024))
        
        err = Decrypt(roundtripbuffer, outbuffer, recipient, func(email []byte) (*rsa.PublicKey, os.Error) {
		return sender, nil
	})
        if err != nil {
		t.Fatalf("failed to decrypt %v", err)
	}
        
        if ! bytes.Equal(roundtripbuffer.Bytes(), payload) {
                t.Fatalf("decrypted payload different from original payload")
        }
}