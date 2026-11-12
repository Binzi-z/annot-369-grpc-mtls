// Package mtls 提供 gRPC mTLS 的热加载证书、TransportCredentials 与指标。
//
// 指标不引第三方依赖，直接渲染 Prometheus 文本格式，
// 由 server 的 /metrics HTTP 端点暴露，Prometheus 抓取即可。
package mtls

import (
	"fmt"
	"net/http"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// Metrics 汇总本节点的 mTLS 运行指标。
//
// 暴露的序列（均带 node 标签）：
//
//	mtls_handshake_failures_total{node,side,reason}  counter  握手失败，reason 粗分类
//	mtls_cert_reload_total{node,result}              counter  热加载尝试结果 ok/error
//	mtls_cert_expiry_seconds{node,cert}              gauge    叶子证书距过期的秒数（倒计时）
//	mtls_ca_bundle_certs{node}                       gauge    当前 CA bundle 里 CA 数量（轮换窗口内为 2）
type Metrics struct {
	node string

	mu            sync.Mutex
	handshakeFail map[string]int64 // key: side|reason
	reload        map[string]int64 // key: result

	leafNotAfterUnix atomic.Int64 // 叶子证书 NotAfter（unix 秒），渲染时算倒计时
	caCount          atomic.Int64
}

func NewMetrics(node string) *Metrics {
	return &Metrics{
		node:          node,
		handshakeFail: map[string]int64{},
		reload:        map[string]int64{},
	}
}

// IncHandshakeFailure 记录一次握手失败。side 为 server/client，reason 见 classifyErr。
func (m *Metrics) IncHandshakeFailure(side, reason string) {
	m.mu.Lock()
	m.handshakeFail[side+"|"+reason]++
	m.mu.Unlock()
}

// IncReload 记录一次热加载结果，result 为 ok 或 error。
func (m *Metrics) IncReload(result string) {
	m.mu.Lock()
	m.reload[result]++
	m.mu.Unlock()
}

// SetLeafExpiry 更新叶子证书过期时间（每次成功加载后调用）。
func (m *Metrics) SetLeafExpiry(notAfter time.Time) {
	m.leafNotAfterUnix.Store(notAfter.Unix())
}

// SetCACount 更新当前 CA bundle 中的 CA 数量。
func (m *Metrics) SetCACount(n int) { m.caCount.Store(int64(n)) }

// Handler 返回渲染 Prometheus 文本格式的 http.Handler（挂到 /metrics）。
func (m *Metrics) Handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain; version=0.0.4")
		var b strings.Builder

		b.WriteString("# HELP mtls_handshake_failures_total TLS handshake failures by side and reason.\n")
		b.WriteString("# TYPE mtls_handshake_failures_total counter\n")
		m.mu.Lock()
		keys := sortedKeys(m.handshakeFail)
		for _, k := range keys {
			side, reason, _ := strings.Cut(k, "|")
			fmt.Fprintf(&b, "mtls_handshake_failures_total{node=%q,side=%q,reason=%q} %d\n",
				m.node, side, reason, m.handshakeFail[k])
		}
		b.WriteString("# HELP mtls_cert_reload_total Cert/CA hot-reload attempts by result.\n")
		b.WriteString("# TYPE mtls_cert_reload_total counter\n")
		for _, k := range sortedKeys(m.reload) {
			fmt.Fprintf(&b, "mtls_cert_reload_total{node=%q,result=%q} %d\n", m.node, k, m.reload[k])
		}
		m.mu.Unlock()

		b.WriteString("# HELP mtls_cert_expiry_seconds Seconds until the leaf certificate expires.\n")
		b.WriteString("# TYPE mtls_cert_expiry_seconds gauge\n")
		if na := m.leafNotAfterUnix.Load(); na > 0 {
			fmt.Fprintf(&b, "mtls_cert_expiry_seconds{node=%q,cert=\"leaf\"} %d\n",
				m.node, na-time.Now().Unix())
		}

		b.WriteString("# HELP mtls_ca_bundle_certs Number of CA certificates in the active bundle.\n")
		b.WriteString("# TYPE mtls_ca_bundle_certs gauge\n")
		fmt.Fprintf(&b, "mtls_ca_bundle_certs{node=%q} %d\n", m.node, m.caCount.Load())

		_, _ = w.Write([]byte(b.String()))
	})
}

func sortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
