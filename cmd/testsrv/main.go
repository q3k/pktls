package main

import (
	"crypto/tls"
	"flag"
	"fmt"
	"net"
	"strings"
	"time"

	"code.hackerspace.pl/q3k/pktls"
	"github.com/golang/glog"
)

var (
	flagListen  string
	flagPrivate string
	flagAllowed string
)

func init() {
	flag.Set("logtostderr", "true")
}

func main() {
	flag.StringVar(&flagListen, "listen", "0.0.0.0:1337", "Listen on address")
	// In production code, do not accept private key literals on the command line,
	// instead read them from a file.
	flag.StringVar(&flagPrivate, "private_key", "", "Server private key")
	flag.StringVar(&flagAllowed, "allowed", "", "Comma-separated list of allowed client public keys")
	flag.Parse()

	if flagPrivate == "" {
		glog.Exitf("-private_key must be set")
	}

	// Parse allowed keys, making them unique and stripping whitespace.
	allowedRaw := strings.Split(flagAllowed, ",")
	allowedSet := make(map[string]bool)
	for _, pk := range allowedRaw {
		pk = strings.TrimSpace(pk)
		if len(pk) == 0 {
			continue
		}
		allowedSet[pk] = true
	}
	var allowed []string
	for pk, _ := range allowedSet {
		allowed = append(allowed, pk)
	}

	pk, err := pktls.ServerFromString(flagPrivate, allowed)
	if err != nil {
		glog.Exitf("loading keys failed: %v", err)
	}

	glog.Infof("Starting with pubkey %s", pk.PrivateKey.Public().String())

	config := tls.Config{}
	err = pk.Configure(&config)
	if err != nil {
		glog.Exitf("pki.Configure: %v", err)
	}

	listener, err := tls.Listen("tcp", flagListen, &config)
	if err != nil {
		glog.Exitf("tcp.Listen(%q): %v", flagListen, err)
	}
	defer listener.Close()

	glog.Infof("Listening on %v", flagListen)

	for {
		cl, err := listener.Accept()
		if err != nil {
			glog.Exitf("Accept failed: %v", err)
		}

		handle(cl)
	}
}

func handle(cl net.Conn) {
	defer cl.Close()

	identity, err := pktls.ClientPubkey(cl)
	if err != nil {
		glog.Infof("%v: could not get identity: %v", cl.RemoteAddr(), err)
		return
	}
	glog.Infof("%v: connected (%v)", cl.RemoteAddr(), identity)

	t := time.NewTicker(1 * time.Second)
	defer t.Stop()

	fmt.Fprintf(cl, "yo\n")
}
