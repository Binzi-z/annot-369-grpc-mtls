package mtls

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"google.golang.org/grpc/credentials"
)

// snapshot 是一次加载得到的原子视图：叶子证书+私钥、CA 池。
// 每次握手整体取一份，避免「证书是新的、CA 还是旧的」这种撕裂状态。
type snapshot struct {
	cert    tls.Certificate
	leaf    *x509.Certificate
	caPool  *x509.CertPool
	caCount int
}

// Reloader 持有证书/CA 文件路径，后台轮询热加载，
// 并实现 credentials.TransportCredentials（server 与 client 通用）。
//
// 热加载不重启进程、不断已有连接：TLS 握手只发生在建连时，
// 已建立的 HTTP/2 连接不受换证书影响。
type Reloader struct {
	node            string
	certFile        string
	keyFile         string
	caFile          string
	isServer        bool
	allowedPeerSANs map[string]bool // 空 = 任意带 SAN 的对端都接受
	reloadInterval  time.Duration
	metrics         *Metrics

	mu         sync.Mutex // 只保护 serverName
	serverName string

	snap atomic.Value // *snapshot

	lastMod map[string]modKey // 仅轮询 goroutine 访问，无需锁
	stop    chan struct{}
}

type modKey struct {
	modTime time.Time
	size    int64
}

// NewServer / NewClient 构造 Reloader 并立即做首次加载（失败直接返回错误，快速失败）。
func NewServer(node, certFile, keyFile, caFile string, allowedPeerSANs []string, reloadInterval time.Duration, m *Metrics) (*Reloader, error) {
	return newReloader(node, certFile, keyFile, caFile, true, allowedPeerSANs, reloadInterval, m)
}

func NewClient(node, certFile, keyFile, caFile string, allowedPeerSANs []string, reloadInterval time.Duration, m *Metrics) (*Reloader, error) {
	return newReloader(node, certFile, keyFile, caFile, false, allowedPeerSANs, reloadInterval, m)
}

func newReloader(node, certFile, keyFile, caFile string, isServer bool, allowed []string, interval time.Duration, m *Metrics) (*Reloader, error) {
	r := &Reloader{
		node:            node,
		certFile:        certFile,
		keyFile:         keyFile,
		caFile:          caFile,
		isServer:        isServer,
		reloadInterval:  interval,
		metrics:         m,
		allowedPeerSANs: map[string]bool{},
		lastMod:         map[string]modKey{},
		stop:            make(chan struct{}),
	}
	for _, s := range allowed {
		r.allowedPeerSANs[s] = true
	}
	if err := r.load(); err != nil {
		return nil, err
	}
	go r.pollLoop()
	return r, nil
}

// Close 停止后台轮询。
func (r *Reloader) Close() { close(r.stop) }

// load 从磁盘读三份文件，全部解析成功后才原子替换快照。
// 任何一步失败都保留旧快照（调用方决定是启动失败还是记指标继续跑）。
func (r *Reloader) load() error {
	cert, err := tls.LoadX509KeyPair(r.certFile, r.keyFile)
	if err != nil {
		return fmt.Errorf("load keypair: %w", err)
	}
	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		return fmt.Errorf("parse leaf: %w", err)
	}
	// 服务身份只认 SAN：server 的叶子证书必须带 SAN，CN-only 直接拒绝加载。
	// client 侧不在加载时卡这条——身份策略由对端（server）在握手时强制，
	// 这样也方便用 CN-only 证书做 server 端的负向测试。
	if r.isServer && !hasSAN(leaf) {
		return errors.New("server leaf certificate has no SAN (CN-only certificates are rejected)")
	}
	if time.Now().After(leaf.NotAfter) {
		return fmt.Errorf("leaf certificate already expired at %s", leaf.NotAfter)
	}

	caPEM, err := os.ReadFile(r.caFile)
	if err != nil {
		return fmt.Errorf("read ca bundle: %w", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM) {
		return errors.New("ca bundle contains no valid CA certificate")
	}
	// 轮换窗口内 bundle 里会有多张 CA（旧+新），数一下用于指标。
	caCount := 0
	for rest := caPEM; ; {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type == "CERTIFICATE" {
			caCount++
		}
	}

	r.snap.Store(&snapshot{cert: cert, leaf: leaf, caPool: pool, caCount: caCount})
	r.metrics.SetLeafExpiry(leaf.NotAfter)
	r.metrics.SetCACount(caCount)
	r.rememberMod()
	return nil
}

func (r *Reloader) rememberMod() {
	for _, f := range []string{r.certFile, r.keyFile, r.caFile} {
		if st, err := os.Stat(f); err == nil {
			r.lastMod[f] = modKey{modTime: st.ModTime(), size: st.Size()}
		}
	}
}

// pollLoop 轮询文件 mtime+size，变化即重载。
// 用轮询而不是 fsnotify：跨平台、对「写临时文件再 rename」的发布方式同样可靠。
func (r *Reloader) pollLoop() {
	t := time.NewTicker(r.reloadInterval)
	defer t.Stop()
	for {
		select {
		case <-r.stop:
			return
		case <-t.C:
			if !r.changed() {
				continue
			}
			if err := r.load(); err != nil {
				// 加载失败保留旧快照继续服务，只记指标/日志告警
				r.metrics.IncReload("error")
				log.Printf("[%s] mtls reload failed (keeping old certs): %v", r.node, err)
				r.rememberMod() // 避免每 2s 重复刷同一条错误
				continue
			}
			r.metrics.IncReload("ok")
			log.Printf("[%s] mtls certs hot-reloaded (ca bundle: %d certs, leaf expires %s)",
				r.node, r.current().caCount, r.current().leaf.NotAfter.Format(time.RFC3339))
		}
	}
}

func (r *Reloader) changed() bool {
	for _, f := range []string{r.certFile, r.keyFile, r.caFile} {
		st, err := os.Stat(f)
		if err != nil {
			continue
		}
		if k, ok := r.lastMod[f]; !ok || k.modTime != st.ModTime() || k.size != st.Size() {
			return true
		}
	}
	return false
}

func (r *Reloader) current() *snapshot { return r.snap.Load().(*snapshot) }

// ---- credentials.TransportCredentials 实现 ----
//
// 关键手法：每次握手用当前快照现造一个 tls.Config 再委托给标准库。
// 这样链验证、主机名验证全部走 crypto/tls 的成熟实现，
// 我们只在握手成功后追加「必须有 SAN / SAN 白名单」的身份策略。

func (r *Reloader) ServerHandshake(conn net.Conn) (net.Conn, credentials.AuthInfo, error) {
	s := r.current()
	cfg := &tls.Config{
		Certificates: []tls.Certificate{s.cert},
		ClientAuth:   tls.RequireAndVerifyClientCert, // 双向校验：客户端必须出证书且能过链验证
		ClientCAs:    s.caPool,
		MinVersion:   tls.VersionTLS12,
	}
	c, ai, err := credentials.NewTLS(cfg).ServerHandshake(conn)
	if err != nil {
		r.metrics.IncHandshakeFailure("server", classifyErr(err))
		return nil, nil, err
	}
	if err := r.checkPeerSAN(ai); err != nil {
		r.metrics.IncHandshakeFailure("server", "san_rejected")
		_ = c.Close()
		return nil, nil, err
	}
	return c, ai, nil
}

func (r *Reloader) ClientHandshake(ctx context.Context, authority string, conn net.Conn) (net.Conn, credentials.AuthInfo, error) {
	s := r.current()
	r.mu.Lock()
	serverName := r.serverName
	r.mu.Unlock()
	if serverName == "" {
		serverName = authority
	}
	cfg := &tls.Config{
		Certificates: []tls.Certificate{s.cert},
		RootCAs:      s.caPool,
		ServerName:   serverName, // 主机名验证只认 SAN（Go>=1.15 起 CN 不再参与）
		MinVersion:   tls.VersionTLS12,
	}
	c, ai, err := credentials.NewTLS(cfg).ClientHandshake(ctx, authority, conn)
	if err != nil {
		r.metrics.IncHandshakeFailure("client", classifyErr(err))
		return nil, nil, err
	}
	if err := r.checkPeerSAN(ai); err != nil {
		r.metrics.IncHandshakeFailure("client", "san_rejected")
		_ = c.Close()
		return nil, nil, err
	}
	return c, ai, nil
}

// checkPeerSAN 强制「SAN 即身份」：对端证书必须带 SAN，且若配置了白名单必须命中。
func (r *Reloader) checkPeerSAN(ai credentials.AuthInfo) error {
	tlsInfo, ok := ai.(credentials.TLSInfo)
	if !ok || len(tlsInfo.State.PeerCertificates) == 0 {
		return errors.New("no peer certificate")
	}
	peer := tlsInfo.State.PeerCertificates[0]
	if !hasSAN(peer) {
		return fmt.Errorf("peer certificate %q has no SAN; CN-only identity is rejected", peer.Subject.CommonName)
	}
	if len(r.allowedPeerSANs) == 0 {
		return nil
	}
	for _, id := range sanIdentities(peer) {
		if r.allowedPeerSANs[id] {
			return nil
		}
	}
	return fmt.Errorf("peer SANs %v not in allowlist", sanIdentities(peer))
}

func (r *Reloader) Info() credentials.ProtocolInfo {
	return credentials.ProtocolInfo{SecurityProtocol: "tls", SecurityVersion: "1.2"}
}

// Clone 返回自身：状态（快照指针、serverName）本就该在克隆间共享。
func (r *Reloader) Clone() credentials.TransportCredentials { return r }

func (r *Reloader) OverrideServerName(name string) error {
	r.mu.Lock()
	r.serverName = name
	r.mu.Unlock()
	return nil
}

// ---- 小工具 ----

func hasSAN(c *x509.Certificate) bool {
	return len(c.DNSNames) > 0 || len(c.IPAddresses) > 0 || len(c.URIs) > 0 || len(c.EmailAddresses) > 0
}

// sanIdentities 汇总证书里的 SAN 身份（URI SAN 与 DNS SAN 都算）。
func sanIdentities(c *x509.Certificate) []string {
	var out []string
	out = append(out, c.DNSNames...)
	for _, u := range c.URIs {
		out = append(out, u.String())
	}
	return out
}

// classifyErr 把握手错误粗分类，作为指标的 reason 标签（控制基数）。
func classifyErr(err error) string {
	msg := err.Error()
	switch {
	case strings.Contains(msg, "unknown certificate authority"),
		strings.Contains(msg, "unknown authority"),
		strings.Contains(msg, "certificate signed by unknown"):
		return "unknown_ca" // 轮换窗口错序时最常见：对端还不认我的新 CA
	case strings.Contains(msg, "expired"):
		return "expired"
	case strings.Contains(msg, "certificate required"),
		strings.Contains(msg, "didn't provide"):
		return "no_client_cert"
	case strings.Contains(msg, "first record does not look like a TLS handshake"):
		return "plaintext" // 明文客户端撞上 mTLS 端口
	default:
		return "other"
	}
}
