package pktls

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"strings"
)

const (
	b64PrefixPublic  = "p1"
	b64PrefixPrivate = "s1"

	keyLength = 32
)

type PublicKey ed25519.PublicKey

type PrivateKey ed25519.PrivateKey

func (p PrivateKey) String() string {
	return b64PrefixPrivate + base64.StdEncoding.EncodeToString(ed25519.PrivateKey(p).Seed())
}

func privateFromBytes(seed []byte) PrivateKey {
	if len(seed) != keyLength {
		panic("seed must be 32 bytes long")
	}
	return PrivateKey(ed25519.NewKeyFromSeed(seed))
}

func PrivateGenerate() (PrivateKey, error) {
	var seed [keyLength]byte
	_, err := rand.Read(seed[:])
	if err != nil {
		return nil, fmt.Errorf("rand.Read: %v", err)
	}
	return privateFromBytes(seed[:]), nil
}

func PrivateFromString(s string) (PrivateKey, error) {
	if !strings.HasPrefix(s, b64PrefixPrivate) {
		if strings.HasPrefix(s, b64PrefixPublic) {
			return nil, fmt.Errorf("invalid key: looks like a public key?")
		}
		return nil, fmt.Errorf("invalid key: not a pktls key")
	}
	s = s[len(b64PrefixPrivate):]
	bytes, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("invalid key: base64 decode failed")
	}
	if len(bytes) != keyLength {
		return nil, fmt.Errorf("invalid key: wrong length")
	}
	return privateFromBytes(bytes), nil
}

func (p PrivateKey) Public() PublicKey {
	return PublicKey(ed25519.PrivateKey(p).Public().(ed25519.PublicKey))
}

func publicFromBytes(pk []byte) PublicKey {
	return PublicKey(pk)
}

func PublicFromString(s string) (PublicKey, error) {
	if !strings.HasPrefix(s, b64PrefixPublic) {
		if strings.HasPrefix(s, b64PrefixPrivate) {
			return nil, fmt.Errorf("invalid key: looks like a private key?")
		}
		return nil, fmt.Errorf("invalid key: not a pktls key")
	}
	s = s[len(b64PrefixPublic):]
	bytes, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("invalid key: base64 decode failed")
	}
	if len(bytes) != keyLength {
		return nil, fmt.Errorf("invalid key: wrong length")
	}
	return publicFromBytes(bytes), nil
}

func (p PublicKey) String() string {
	return b64PrefixPublic + base64.StdEncoding.EncodeToString(p)
}
