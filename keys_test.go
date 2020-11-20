package pktls

import (
	"bytes"
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"testing"
)

func TestPrivateIO(t *testing.T) {
	priv1, err := PrivateGenerate()
	if err != nil {
		t.Fatalf("PrivateGenerate: %v", err)
	}

	str := priv1.String()
	priv2, err := PrivateFromString(str)
	if err != nil {
		t.Fatalf("PrivateFromString: %v", err)
	}

	// TODO(q3k): use ed25519.PrivateKey.Equal when go 1.15 becomes a bit more mainstream
	if !bytes.Equal(priv1, priv2) {
		t.Fatalf("private key re-read from string differs from original")
	}
}

func TestPublicIO(t *testing.T) {
	priv1, err := PrivateGenerate()
	if err != nil {
		t.Fatalf("PrivateGenerate: %v", err)
	}
	pub1 := priv1.Public()

	str := pub1.String()
	pub2, err := PublicFromString(str)
	if err != nil {
		t.Fatalf("PublicFromString: %v", err)
	}

	// TODO(q3k): use ed25519.PublicKey.Equal when go 1.15 becomes a bit more mainstream
	if !bytes.Equal(pub1, pub2) {
		t.Fatalf("public key re-read from string differs from original")
	}
}

func TestE2E(t *testing.T) {
	// genkey equivalent
	priv1, err := PrivateGenerate()
	if err != nil {
		t.Fatalf("PrivateGenerate: %v", err)
	}
	priv := priv1.String()

	// pubkey equivalent
	priv2, err := PrivateFromString(priv)
	if err != nil {
		t.Fatalf("PrivateFromString: %v", err)
	}
	pub := priv2.Public().String()

	// sender equivalent
	msg := []byte("ahou")
	sig, err := ed25519.PrivateKey(priv2).Sign(rand.Reader, msg, crypto.Hash(0))
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}

	// receiver equivalent
	pub1, err := PublicFromString(pub)
	if err != nil {
		t.Fatalf("PublicFromString: %v", err)
	}

	if !ed25519.Verify(ed25519.PublicKey(pub1), msg, sig) {
		t.Fatalf("Signature verification failed")
	}
}
