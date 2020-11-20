package pktls

import (
	"bytes"
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha1"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"time"
)

type TLSMode int

const (
	TLSServer TLSMode = iota
	TLSClient
)

var (
	// From RFC 5280 Section 4.1.2.5
	unknownNotAfter = time.Unix(253402300799, 0)

	ErrWrongIdentity = errors.New("unknown identity")
)

// Workaround for https://github.com/golang/go/issues/26676 in Go's crypto/x509. Specifically Go
// violates Section 4.2.1.2 of RFC 5280 without this.
// Fixed for 1.15 in https://go-review.googlesource.com/c/go/+/227098/.
//
// Taken from https://github.com/FiloSottile/mkcert/blob/master/cert.go#L295 written by one of Go's
// crypto engineers
func calculateSKID(pubKey crypto.PublicKey) ([]byte, error) {
	spkiASN1, err := x509.MarshalPKIXPublicKey(pubKey)
	if err != nil {
		return nil, err
	}

	var spki struct {
		Algorithm        pkix.AlgorithmIdentifier
		SubjectPublicKey asn1.BitString
	}
	_, err = asn1.Unmarshal(spkiASN1, &spki)
	if err != nil {
		return nil, err
	}
	skid := sha1.Sum(spki.SubjectPublicKey.Bytes)
	return skid[:], nil
}

func (p PrivateKey) GenerateTLS(mode TLSMode) (*tls.Certificate, error) {
	private := ed25519.PrivateKey(p)
	public := private.Public()

	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 127)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return nil, fmt.Errorf("failed to generate serial number: %w", err)
	}

	skid, err := calculateSKID(public)
	if err != nil {
		return nil, fmt.Errorf("failed to calculate subject key DI: %w", err)
	}

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{"pktls"},
		},
		NotBefore:             time.Now(),
		NotAfter:              unknownNotAfter,
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		SubjectKeyId:          skid,
		AuthorityKeyId:        skid,
	}

	switch mode {
	case TLSServer:
		template.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
	case TLSClient:
		template.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
	default:
		return nil, fmt.Errorf("invalid TLS mode argument")
	}

	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, public, private)
	if err != nil {
		return nil, fmt.Errorf("failed to sign certificate: %w", err)
	}

	keyDER, err := x509.MarshalPKCS8PrivateKey(private)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal private key: %w", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})

	tlsCert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, fmt.Errorf("failed to use new certificate: %w", err)
	}
	return &tlsCert, nil
}

func parseCertificate(cert *x509.Certificate) (PublicKey, error) {
	if cert.PublicKeyAlgorithm != x509.Ed25519 {
		return nil, fmt.Errorf("certificate subject public key algorithm not ED25519")
	}
	presented := cert.PublicKey.(ed25519.PublicKey)
	if len(presented) != keyLength {
		return nil, fmt.Errorf("%w: pubkey invalid", ErrWrongIdentity)
	}
	return publicFromBytes(presented), nil
}

func (p PublicKey) Verify(mode TLSMode, pem []byte) error {
	cert, err := x509.ParseCertificate(pem)
	if err != nil {
		return err
	}
	presented, err := parseCertificate(cert)
	if err != nil {
		return err
	}
	if !bytes.Equal(presented, p) {
		return fmt.Errorf("%w: pubkey %s", ErrWrongIdentity, presented.String())
	}

	for _, ku := range cert.ExtKeyUsage {
		switch mode {
		case TLSServer:
			if ku == x509.ExtKeyUsageClientAuth {
				return nil
			}
		case TLSClient:
			if ku == x509.ExtKeyUsageServerAuth {
				return nil
			}
		}
	}

	return fmt.Errorf("%w: pubkey not valid for this mode", ErrWrongIdentity)
}

func ClientPubkey(c net.Conn) (*PublicKey, error) {
	inner, ok := c.(*tls.Conn)
	if !ok {
		return nil, fmt.Errorf("not a TLS connection")
	}
	if err := inner.Handshake(); err != nil {
		return nil, fmt.Errorf("handshake failed: %w", err)
	}

	state := inner.ConnectionState()
	pubkey, err := parseCertificate(state.PeerCertificates[0])
	if err != nil {
		return nil, fmt.Errorf("internal error: invalid certificate: %w", err)
	}
	return &pubkey, nil
}
