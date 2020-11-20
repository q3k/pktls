package pktls

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
)

type Config struct {
	PrivateKey PrivateKey
}

type ServerConfig struct {
	Config
	Allowed []PublicKey
}

type ClientConfig struct {
	Config
	Server PublicKey
}

func ServerFromString(privkey string, allowed []string) (*ServerConfig, error) {
	if len(allowed) == 0 {
		return nil, fmt.Errorf("no allowed keys set, server will accept no clients")
	}
	priv, err := PrivateFromString(privkey)
	if err != nil {
		return nil, fmt.Errorf("server private key: %w", err)
	}

	allowedKeys := make([]PublicKey, len(allowed))
	for i, pk := range allowed {
		public, err := PublicFromString(pk)
		if err != nil {
			return nil, fmt.Errorf("allowed key %d: %w", i, err)
		}
		allowedKeys[i] = public
	}
	cfg := &ServerConfig{
		Config: Config{
			PrivateKey: priv,
		},
		Allowed: allowedKeys,
	}

	return cfg, nil
}

func ClientFromString(privkey string, server string) (*ClientConfig, error) {
	priv, err := PrivateFromString(privkey)
	if err != nil {
		return nil, fmt.Errorf("client private key: %w", err)
	}
	serverKey, err := PublicFromString(server)
	if err != nil {
		return nil, fmt.Errorf("server public key: %w", err)
	}
	cfg := &ClientConfig{
		Config: Config{
			PrivateKey: priv,
		},
		Server: serverKey,
	}

	return cfg, nil
}
func (s *ServerConfig) Configure(config *tls.Config) error {
	tlsCert, err := s.PrivateKey.GenerateTLS(TLSServer)
	if err != nil {
		return fmt.Errorf("generating TLS certificate/keypair failed: %w", err)
	}
	config.Certificates = []tls.Certificate{*tlsCert}
	config.ClientAuth = tls.RequireAnyClientCert
	config.VerifyPeerCertificate = s.VerifyPeerCertificate
	return nil
}

func (s *ServerConfig) VerifyPeerCertificate(rawCerts [][]byte, _ [][]*x509.Certificate) error {
	if len(rawCerts) != 1 {
		return fmt.Errorf("need exacty one client certificate")
	}
	cert := rawCerts[0]

	lastErr := ErrWrongIdentity
	for _, allowed := range s.Allowed {
		err := allowed.Verify(TLSServer, cert)
		switch {
		case err == nil:
			return nil
		case errors.Is(err, ErrWrongIdentity):
			lastErr = err
			continue
		default:
			return err
		}
	}

	return lastErr
}

func (c *ClientConfig) Configure(config *tls.Config) error {
	tlsCert, err := c.PrivateKey.GenerateTLS(TLSClient)
	if err != nil {
		return fmt.Errorf("generating TLS certificate/keypair failed: %w", err)
	}
	config.Certificates = []tls.Certificate{*tlsCert}
	config.InsecureSkipVerify = true
	config.VerifyPeerCertificate = c.VerifyPeerCertificate
	return nil
}

func (c *ClientConfig) VerifyPeerCertificate(rawCerts [][]byte, _ [][]*x509.Certificate) error {
	if len(rawCerts) != 1 {
		return fmt.Errorf("need exacty one server certificate")
	}
	cert := rawCerts[0]
	return c.Server.Verify(TLSClient, cert)
}
