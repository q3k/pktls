package main

import (
	"crypto/tls"
	"flag"
	"io"
	"os"

	"code.hackerspace.pl/q3k/pktls"
	"github.com/golang/glog"
)

var (
	flagRemote     string
	flagPrivateKey string
	flagRemoteKey  string
)

func init() {
	flag.Set("logtostderr", "true")
}

func main() {
	flag.StringVar(&flagRemote, "remote", "127.0.0.1:1337", "Server address")
	// In production code, do not accept private key literals on the command line,
	// instead read them from a file.
	flag.StringVar(&flagPrivateKey, "private_key", "", "Client private key")
	flag.StringVar(&flagRemoteKey, "remote_key", "", "Server public key")
	flag.Parse()

	if flagPrivateKey == "" {
		glog.Exitf("-private_key must be set")
	}

	if flagRemoteKey == "" {
		glog.Exitf("-remote_key must be set")
	}

	pk, err := pktls.ClientFromString(flagPrivateKey, flagRemoteKey)
	if err != nil {
		glog.Exitf("loading keys failed: %v", err)
	}

	glog.Infof("Connecting with pubkey %s", pk.PrivateKey.Public().String())

	config := tls.Config{}
	err = pk.Configure(&config)
	if err != nil {
		glog.Exitf("pki.Configure: %v", err)
	}

	conn, err := tls.Dial("tcp", flagRemote, &config)
	if err != nil {
		glog.Exitf("Dial: %v", err)
	}
	_, err = io.Copy(os.Stdout, conn)
	if err != nil && err != io.EOF {
		glog.Exitf("Copy failed: %v", err)
	}
}
