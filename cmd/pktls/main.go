package main

import (
	"bufio"
	"fmt"
	"io"
	"log"
	"os"

	"code.hackerspace.pl/q3k/pktls"
)

func usage(cmd string) {
	fmt.Fprintf(os.Stderr, `Usage: %s <subcommand>

Available subcommands:
  genkey: Generates a new private key and writes it to stdout
  pubkey: Reads a private key from stdin and writes a public key to stdout
`, cmd)
}

func main() {
	switch len(os.Args) {
	case 0:
		// This should never happen.
		panic("no argv?")
	case 1:
		usage(os.Args[0])
	default:
		switch os.Args[1] {
		case "genkey":
			genkey()
		case "pubkey":
			pubkey()
		default:
			usage(os.Args[0])
		}
	}
}

func genkey() {
	key, err := pktls.PrivateGenerate()
	if err != nil {
		log.Fatalf("Generation failed: %v", err)
	}
	fmt.Printf("%s\n", key.String())
}

func pubkey() {
	r := bufio.NewReader(os.Stdin)
	data, err := r.ReadString('\n')
	if err != nil && err != io.EOF {
		log.Fatalf("Read from stdin failed: %v", err)
	}
	priv, err := pktls.PrivateFromString(data)
	if err != nil {
		log.Fatalf("Private key read failed: %v", err)
	}
	fmt.Printf("%s\n", priv.Public().String())
}
