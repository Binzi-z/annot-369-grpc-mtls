// gencerts：生成本地 mTLS 演练所需的全部证书物料。
//
//	go run ./cmd/gencerts -out certs -days 30
//
// 产物（-out 目录下）：
//
//	CA：       ca-old.pem/ca-old-key.pem      当前 CA（ca.pem 是它的别名，兼容旧用法）
//	           ca-new.pem/ca-new-key.pem      轮换目标 CA
//	bundle：   bundle-old.pem                 只含旧 CA（稳态）
//	           bundle-rotation.pem            旧+新 CA（轮换窗口内分发到全集群）
//	           bundle-new.pem                 只含新 CA（轮换完成后的稳态）
//	server：   server-<node>.pem/-key.pem         每个节点一张，旧 CA 签发
//	           server-<node>-new.pem/-key.pem     同节点、新 CA 签发（轮换用）
//	           server.pem/server-key.pem          第一个节点的别名，兼容默认参数
//	           SAN：DNS=localhost,<node>，IP=127.0.0.1，URI=spiffe://annot/node/<node>
//	client：   client.pem/client-key.pem          旧 CA 签发，URI SAN=spiffe://annot/client
//	           client-new.pem/client-key.pem      新 CA 签发（轮换用）
//	           client-cn-only.pem/-key.pem        只有 CN、没有 SAN（负向测试：必须被拒绝）
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
	"net/url"
	"os"
	"path/filepath"
	"strings"
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

// appendFile 把 src 内容追加到 dst（拼 CA bundle 用）。
func appendFile(dst, src string) {
	data, err := os.ReadFile(src)
	if err != nil {
		log.Fatalf("read %s: %v", src, err)
	}
	f, err := os.OpenFile(dst, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		log.Fatalf("open %s: %v", dst, err)
	}
	defer f.Close()
	if _, err := f.Write(data); err != nil {
		log.Fatalf("append %s: %v", dst, err)
	}
}

func copyFile(dst, src string) {
	data, err := os.ReadFile(src)
	if err != nil {
		log.Fatalf("read %s: %v", src, err)
	}
	if err := os.WriteFile(dst, data, 0o644); err != nil {
		log.Fatalf("write %s: %v", dst, err)
	}
}

func newKey() *ecdsa.PrivateKey {
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		log.Fatalf("gen key: %v", err)
	}
	return k
}

func newCA(out, name string, days int) (*x509.Certificate, *ecdsa.PrivateKey) {
	key := newKey()
	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	tpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: name, Organization: []string{"annot"}},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Duration(days) * 24 * time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		log.Fatalf("create ca %s: %v", name, err)
	}
	writePem(filepath.Join(out, name+".pem"), "CERTIFICATE", der)
	keyDER, _ := x509.MarshalECPrivateKey(key)
	writePem(filepath.Join(out, name+"-key.pem"), "EC PRIVATE KEY", keyDER)
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		log.Fatalf("parse ca: %v", err)
	}
	return cert, key
}

// issueLeaf 用 ca 签一张叶子证书。dnsNames/uris/ips 全空则生成 CN-only 证书（负向测试用）。
func issueLeaf(out, name, cn string, ca *x509.Certificate, caKey *ecdsa.PrivateKey, days int,
	eku []x509.ExtKeyUsage, dnsNames []string, uris []string, ips []string) {

	key := newKey()
	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	tpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: cn, Organization: []string{"annot"}},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Duration(days) * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  eku,
		DNSNames:     dnsNames,
	}
	for _, u := range uris {
		parsed, err := url.Parse(u)
		if err != nil {
			log.Fatalf("bad uri san %q: %v", u, err)
		}
		tpl.URIs = append(tpl.URIs, parsed)
	}
	for _, ip := range ips {
		tpl.IPAddresses = append(tpl.IPAddresses, net.ParseIP(ip))
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, ca, &key.PublicKey, caKey)
	if err != nil {
		log.Fatalf("create %s: %v", name, err)
	}
	writePem(filepath.Join(out, name+".pem"), "CERTIFICATE", der)
	keyDER, _ := x509.MarshalECPrivateKey(key)
	writePem(filepath.Join(out, name+"-key.pem"), "EC PRIVATE KEY", keyDER)
}

func main() {
	out := flag.String("out", "certs", "output dir")
	days := flag.Int("days", 30, "validity days")
	nodes := flag.String("nodes", "node-a,node-b,node-c", "comma-separated node ids")
	flag.Parse()
	mustMkdir(*out)

	caOld, caOldKey := newCA(*out, "ca-old", *days)
	caNew, caNewKey := newCA(*out, "ca-new", *days)

	// CA bundle：稳态（只含一个 CA）与轮换窗口（旧+新）
	old := filepath.Join(*out, "ca-old.pem")
	newP := filepath.Join(*out, "ca-new.pem")
	copyFile(filepath.Join(*out, "bundle-old.pem"), old)
	copyFile(filepath.Join(*out, "bundle-new.pem"), newP)
	copyFile(filepath.Join(*out, "bundle-rotation.pem"), old)
	appendFile(filepath.Join(*out, "bundle-rotation.pem"), newP)
	// 兼容旧用法的别名
	copyFile(filepath.Join(*out, "ca.pem"), old)

	serverEKU := []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
	clientEKU := []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
	loopback := []string{"127.0.0.1", "::1"}

	nodeList := strings.Split(*nodes, ",")
	for i, n := range nodeList {
		n = strings.TrimSpace(n)
		dns := []string{"localhost", n}
		uri := []string{"spiffe://annot/node/" + n}
		issueLeaf(*out, "server-"+n, n, caOld, caOldKey, *days, serverEKU, dns, uri, loopback)
		issueLeaf(*out, "server-"+n+"-new", n, caNew, caNewKey, *days, serverEKU, dns, uri, loopback)
		if i == 0 { // 默认参数别名
			copyFile(filepath.Join(*out, "server.pem"), filepath.Join(*out, "server-"+n+".pem"))
			copyFile(filepath.Join(*out, "server-key.pem"), filepath.Join(*out, "server-"+n+"-key.pem"))
		}
	}

	issueLeaf(*out, "client", "echo-client", caOld, caOldKey, *days, clientEKU,
		[]string{"echo-client"}, []string{"spiffe://annot/client"}, nil)
	issueLeaf(*out, "client-new", "echo-client", caNew, caNewKey, *days, clientEKU,
		[]string{"echo-client"}, []string{"spiffe://annot/client"}, nil)
	// 负向测试：只有 CN、没有任何 SAN，必须被 server 拒绝
	issueLeaf(*out, "client-cn-only", "sneaky-client", caOld, caOldKey, *days, clientEKU, nil, nil, nil)

	log.Printf("certs written to %s (valid %d days, nodes: %s)", *out, *days, *nodes)
}
