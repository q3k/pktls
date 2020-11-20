pktls
=====

**DO NOT USE THIS (YET), UNAUDITED, PRE-RELEASE.**

Description
-----------

A Go library to allow using wireguard-style asymmetric keys to configure mutual TLS authentication.


    .-------------.
    | Server      |
    |-------------|                      .--------------.
    | server.priv |                      | Client 1     |
    |             | <---- TLS -----.---- |--------------|
    | client1.pub |                |     | client1.priv |
    | client2.pub |                |     | server.pub   |
    '-------------'                |     '--------------'
                                   |     .--------------.
                                   |     | Client 2     |
                                   '---- |--------------|
                                         | client2.priv |
                                         | server.pub   |
                                         '--------------'

No more having to deal with openssl, CAs, expiring certificates, and complex x509 bootstrap - just use genkey/pubkey!

Under the hood, it uses ED25519 to generate self-signed certificates for both sides.o

Key Generation
--------------

    go get code.hackerspace.pl/q3k/pktls
    go build code.hackerspace.pl/q3k/pkgtls/cmd/pktls

    ./pktls genkey > server.priv
    ./pktls pubkey < server.priv > server.pub

The resulting keys look very much like wireguard keys, but are _not compatible_. pktls keys will not work as wireguard keys, and vice-versa.

Library usage
-------------

On the server side:

    pk, err := pktls.ServerFromString("<private key>", []string{"<client public key>", "<client public key>"}) 
    config := tls.Config{}
    pk.Configure(&config)
    // Use config with tls.Listen, grpc/credentials.NewTLS, etc.

On the client side:

    pk, err := pktls.ClientFromString("<private key>", "<server public key>")
    config := tls.Config{}
    pk.Configure(&config)
    // Use config with tls.Dial, grpc/credentials.NewTLS, etc.

For example code, see cmd/test{srv,cl}.

Sample client/server
--------------------

To test this library without writing Go, you can run a pktls server/client pair as following:

    
    go get code.hackerspace.pl/q3k/pktls
    go build code.hackerspace.pl/q3k/pkgtls/cmd/pktls

    ./pktls genkey > server.priv
    ./pktls pubkey < server.priv > server.pub
    ./pktls genkey > client.priv
    ./pktls pubkey < client.priv > client.pub

    go build code.hackerspace.pl/q3k/pkgtls/cmd/testsrv
    ./testsrv -private_key $(cat server.priv) -allowed $(cat client.pub) -listen 127.0.0.1:1337

    # and on another terminal:
    go build code.hackerspace.pl/q3k/pkgtls/cmd/testcl
    ./testcl -private_key $(cat client.priv) -remote_key $(cat server.pub) -remote 127.0.0.1:1337

You should observe the client receiving a hello message from the server (”yo”), and the server being able to introspect the identity of the client.

