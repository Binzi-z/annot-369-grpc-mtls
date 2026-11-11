// gencerts：生成一套 CA + server + client 证书（本地演示用）。
//
//	go run ./cmd/gencerts -out certs -days 30
//
// 产物：
//   certs/ca.pem  ca-key.pem
//   certs/server.pem server-key.pem
//   certs/client.pem client-key.pem
//
// 说明：这是给改造阶段用的素材，基线（明文）不读取它们。
package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"flag"
	"log"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"time"
)

func mustMkdir(p string) { _ = os.MkdirAll(p, 0o755) }

func writePem(path, typ string, der []byte) {
	f, err := os.Create(path)
	if err != nil {
		log.Fatalf("create %s: %v", path, err)
	}
	defer f.Close()
	if err := pem.Encode(f, &pem.Block{Type: typ, Bytes: der}); err != nil {
		log.Fatalf("encode %s: %v", path, err)
	}
}

func newKey() *ecdsa.PrivateKey {
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		log.Fatalf("gen key: %v", err)
	}
	return k
}

func main() {
	out := flag.String("out", "certs", "output dir")
	days := flag.Int("days", 30, "validity days")
	flag.Parse()
	mustMkdir(*out)

	now := time.Now()
	caKey := newKey()
	caTpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "annot-demo-ca", Organization: []string{"annot"}},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(time.Duration(*days) * 24 * time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTpl, caTpl, &caKey.PublicKey, caKey)
	if err != nil {
		log.Fatalf("create ca: %v", err)
	}
	writePem(filepath.Join(*out, "ca.pem"), "CERTIFICATE", caDER)
	caKeyDER, _ := x509.MarshalECPrivateKey(caKey)
	writePem(filepath.Join(*out, "ca-key.pem"), "EC PRIVATE KEY", caKeyDER)

	caCert, err := x509.ParseCertificate(caDER)
	if err != nil {
		log.Fatalf("parse ca: %v", err)
	}

	// server
	srvKey := newKey()
	srvTpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "echo-server", Organization: []string{"annot"}},
		NotBefore:    now.Add(-time.Hour),
		NotAfter:     now.Add(time.Duration(*days) * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{"localhost", "echo-server"},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")},
	}
	srvDER, err := x509.CreateCertificate(rand.Reader, srvTpl, caCert, &srvKey.PublicKey, caKey)
	if err != nil {
		log.Fatalf("create server cert: %v", err)
	}
	writePem(filepath.Join(*out, "server.pem"), "CERTIFICATE", srvDER)
	srvKeyDER, _ := x509.MarshalECPrivateKey(srvKey)
	writePem(filepath.Join(*out, "server-key.pem"), "EC PRIVATE KEY", srvKeyDER)

	// client
	cliKey := newKey()
	cliTpl := &x509.Certificate{
		SerialNumber: big.NewInt(3),
		Subject:      pkix.Name{CommonName: "echo-client", Organization: []string{"annot"}},
		NotBefore:    now.Add(-time.Hour),
		NotAfter:     now.Add(time.Duration(*days) * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	cliDER, err := x509.CreateCertificate(rand.Reader, cliTpl, caCert, &cliKey.PublicKey, caKey)
	if err != nil {
		log.Fatalf("create client cert: %v", err)
	}
	writePem(filepath.Join(*out, "client.pem"), "CERTIFICATE", cliDER)
	cliKeyDER, _ := x509.MarshalECPrivateKey(cliKey)
	writePem(filepath.Join(*out, "client-key.pem"), "EC PRIVATE KEY", cliKeyDER)

	log.Printf("certs written to %s (valid %d days)", *out, *days)
}
