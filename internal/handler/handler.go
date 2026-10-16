package handler

import (
	"context"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	proxydialer "github.com/elastic/proxy-connect-dialer-go"
	"golang.org/x/net/proxy"

	"tls10proxy/internal/ca"
	"tls10proxy/internal/config"
	"tls10proxy/internal/logger"
)

const CLDC11 string = "Configuration/CLDC-1.1"

// Hop-by-hop headers to exclude from responses
var hopByHopHeaders = map[string]bool{
	"Connection":          true,
	"Keep-Alive":          true,
	"Proxy-Authenticate":  true,
	"Proxy-Authorization": true,
	"Te":                  true,
	"Trailers":            true,
	"Transfer-Encoding":   true,
	"Upgrade":             true,
	"Proxy-Connection":    true,
}

func init() {
	proxy.RegisterDialerType("http", func(u *url.URL, d proxy.Dialer) (proxy.Dialer, error) {
		return proxydialer.NewProxyConnectDialer(u, d)
	})

	proxy.RegisterDialerType("https", func(u *url.URL, d proxy.Dialer) (proxy.Dialer, error) {
		return proxydialer.NewProxyConnectDialer(u, d)
	})
}

func (h *ProxyHandler) getServerCert(hostname string) (*tls.Certificate, error) {
	h.cacheLock.RLock()
	if cert, ok := h.certCache[hostname]; ok {
		if cert.Leaf != nil && cert.Leaf.NotAfter.After(time.Now()) {
			h.cacheLock.RUnlock()
			return cert, nil
		}
	}
	h.cacheLock.RUnlock()

	h.cacheLock.Lock()
	defer h.cacheLock.Unlock()

	if cert, ok := h.certCache[hostname]; ok && cert.Leaf != nil && cert.Leaf.NotAfter.After(time.Now()) {
		return cert, nil
	}

	cert, err := ca.GenerateServerCert(hostname, h.caCert, h.caKey)
	if err != nil {
		return nil, err
	}

	h.certCache[hostname] = cert
	return cert, nil
}

func createDownstreamTLSConfig(cert *tls.Certificate) *tls.Config {
	return &tls.Config{
		Certificates: []tls.Certificate{*cert},
		MinVersion:   0x0301, // TLS 1.0
		MaxVersion:   0x0301,
		CipherSuites: []uint16{
			tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
			tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
			tls.TLS_RSA_WITH_AES_128_CBC_SHA,
			tls.TLS_RSA_WITH_AES_256_CBC_SHA,
		},
	}
}

const COPY_BUFFER_SIZE = 128 * 1024

var copyBufPool = sync.Pool{
	New: func() any {
		b := make([]byte, COPY_BUFFER_SIZE)
		return &b
	},
}

func copyWithPool(dst io.Writer, src io.Reader) {
	bufp := copyBufPool.Get().(*[]byte)
	defer copyBufPool.Put(bufp)
	io.CopyBuffer(dst, src, *bufp)
}

func relay(clientConn, upstreamConn net.Conn) {
	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		defer clientConn.Close()
		defer upstreamConn.Close()
		copyWithPool(clientConn, upstreamConn)
	}()

	go func() {
		defer wg.Done()
		defer clientConn.Close()
		defer upstreamConn.Close()
		copyWithPool(upstreamConn, clientConn)
	}()

	wg.Wait()
}

func ProxyErrorUnauthorized(w http.ResponseWriter) {
	w.Header().Add("WWW-Authenticate", "Basic realm=\"TLS10PROXY\"")
	http.Error(w, "Authorization required", http.StatusUnauthorized)
}

type AllowedUsers struct {
	Subnet    map[string]struct{}
	UserAgent map[string]struct{}
}

type ProxyHandler struct {
	cfg              config.Config
	caCert           *x509.Certificate
	caKey            *rsa.PrivateKey
	certCache        map[string]*tls.Certificate
	cacheLock        sync.RWMutex
	proxyDialContext func(ctx context.Context, network, addr string) (net.Conn, error)
	AllowedUsers
	AllowedUsersLock sync.RWMutex
}

func NewProxyHandler(cfg config.Config, caCert *x509.Certificate, caKey *rsa.PrivateKey) (*ProxyHandler, error) {
	var proxyDialCtx func(ctx context.Context, network, addr string) (net.Conn, error)

	if cfg.ProxyURL != "" {
		u, err := url.Parse(cfg.ProxyURL)
		if err != nil {
			return nil, fmt.Errorf("invalid proxy URL: %w", err)
		}

		dialer, err := proxy.FromURL(u, proxy.Direct)
		if err != nil {
			return nil, fmt.Errorf("failed to create proxy dialer: %w", err)
		}

		// Extract DialContext once during initialization
		if dc, ok := dialer.(interface {
			DialContext(ctx context.Context, network, addr string) (net.Conn, error)
		}); ok {
			proxyDialCtx = dc.DialContext
		} else {
			// Fallback for dialers that only implement synchronous Dial
			proxyDialCtx = func(ctx context.Context, network, addr string) (net.Conn, error) {
				return dialer.Dial(network, addr)
			}
		}
	}

	return &ProxyHandler{
		cfg:              cfg,
		caCert:           caCert,
		caKey:            caKey,
		certCache:        make(map[string]*tls.Certificate),
		proxyDialContext: proxyDialCtx,
		AllowedUsers:     AllowedUsers{Subnet: make(map[string]struct{}), UserAgent: make(map[string]struct{})},
	}, nil
}

func ExtractSubnet(ip string, mask int) string {
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return ""
	}
	ip4 := parsed.To4()
	if ip4 == nil {
		return ""
	}
	if mask < 0 || mask > 32 {
		return ""
	}
	m := net.CIDRMask(mask, 32)
	return (&net.IPNet{IP: ip4.Mask(m), Mask: m}).String()
}

func (h *ProxyHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	userAgent := r.UserAgent()

	if h.cfg.LogRequests {
		logger.Infof("Request: %v %v %v %v %v", r.RemoteAddr, r.Proto, r.Method, r.URL, userAgent)
	}

	// Credential check if auth enabled
	if h.cfg.Credentials != "" {
		allowed := false
		clientIP, _, err := net.SplitHostPort(r.RemoteAddr)
		if err != nil {
			clientIP = r.RemoteAddr
		}
		clientSubnet := ""

		if h.cfg.CaptiveFallback {
			clientSubnet = ExtractSubnet(clientIP, h.cfg.CaptiveSubnet)

			h.AllowedUsersLock.RLock()
			_, subnetFound := h.AllowedUsers.Subnet[clientSubnet]
			_, userAgentFound := h.AllowedUsers.UserAgent[userAgent]
			if subnetFound {
				if userAgentFound {
					allowed = true
				} else {
					for storedUA, _ := range h.AllowedUsers.UserAgent {
						if strings.HasPrefix(userAgent, storedUA) {
							allowed = true
							break
						}
					}
				}
			}
			h.AllowedUsersLock.RUnlock()
		}

		if !allowed {
			h.handleAuth(clientIP, clientSubnet, userAgent, w, r)
			return
		}
	}

	if r.Method == http.MethodConnect {
		h.handleConnect(w, r)
		return
	}

	h.handleHTTP(w, r)
}

func (h *ProxyHandler) handleAuth(clientIP string, clientSubnet string, userAgent string, w http.ResponseWriter, r *http.Request) {
	credsB64 := r.Header.Get("Proxy-Authorization")
	if credsB64 == "" {
		if h.cfg.CaptiveFallback {
			credsB64 = r.Header.Get("Authorization")
		}
		if credsB64 == "" {
			ProxyErrorUnauthorized(w)
			logger.Warnf("%s No credentials provided", r.RemoteAddr)
			return
		}
	}

	if !strings.HasPrefix(strings.ToLower(credsB64), "basic ") {
		ProxyErrorUnauthorized(w)
		logger.Errorf("%s Error decoding proxy credentials", r.RemoteAddr)
		return
	}

	credsB64 = strings.TrimSpace(credsB64[6:])

	creds, err := base64.StdEncoding.DecodeString(credsB64)
	if err != nil {
		ProxyErrorUnauthorized(w)
		logger.Errorf("%s Error decoding proxy credentials: %v", r.RemoteAddr, err)
		return
	}

	if string(creds) != h.cfg.Credentials {
		ProxyErrorUnauthorized(w)
		logger.Warnf("%s Credentials mismatch (got %s)", r.RemoteAddr, string(creds))
		return
	}

	if h.cfg.CaptiveFallback {
		h.AllowedUsersLock.Lock()
		h.AllowedUsers.Subnet[clientSubnet] = struct{}{}
		logger.Infof("Subnet saved: %s", clientSubnet)
		h.AllowedUsers.UserAgent[userAgent] = struct{}{}
		// Also adds a separate user-agent for j2me apps
		if i := strings.Index(userAgent, CLDC11); i != -1 {
			userAgentJ2ME := userAgent[:i+len(CLDC11)]
			h.AllowedUsers.UserAgent[userAgentJ2ME] = struct{}{}
			logger.Infof("User-Agent saved: %s", userAgentJ2ME)
		}
		logger.Infof("User-Agent saved: %s", userAgent)

		h.AllowedUsersLock.Unlock()
	}

	logger.Infof("%s Successfully authorized", clientIP)
	http.Redirect(w, r, r.RequestURI, http.StatusMovedPermanently)
	return
}

func (h *ProxyHandler) handleConnect(w http.ResponseWriter, r *http.Request) {
	status := http.StatusOK

	hostPort := r.URL.Host
	if hostPort == "" {
		status = http.StatusBadRequest
		http.Error(w, "Bad Request: Invalid CONNECT target", status)
		return
	}

	hostname, port, err := net.SplitHostPort(hostPort)
	if err != nil {
		hostname = hostPort
		port = "443"
	}

	var upstreamConn net.Conn
	targetAddr := net.JoinHostPort(hostname, port)
	tlsConfig := &tls.Config{
		ServerName:         hostname,
		InsecureSkipVerify: false,
	}

	if h.proxyDialContext != nil {
		var rawConn net.Conn
		rawConn, err = h.proxyDialContext(r.Context(), "tcp", targetAddr)
		if err != nil {
			status = http.StatusBadGateway
			http.Error(w, fmt.Sprintf("Bad Gateway (Proxy Dial): %v", err), status)
			logger.Errorf("Error connecting to proxy: %v", err)
			return
		}

		tlsConn := tls.Client(rawConn, tlsConfig)
		if err = tlsConn.Handshake(); err != nil {
			status = http.StatusBadGateway
			http.Error(w, fmt.Sprintf("Bad Gateway (TLS Handshake): %v", err), status)
			logger.Errorf("Error connecting to proxy: %v", err)
			tlsConn.Close()
			return
		}
		upstreamConn = tlsConn
	} else {
		var tlsConn net.Conn
		tlsConn, err = tls.Dial("tcp", targetAddr, tlsConfig)
		if err != nil {
			status = http.StatusBadGateway
			http.Error(w, fmt.Sprintf("Bad Gateway: %v", err), status)
			return
		}
		upstreamConn = tlsConn
	}

	hijacker, ok := w.(http.Hijacker)
	if !ok {
		status = http.StatusInternalServerError
		http.Error(w, "Hijacking not supported", status)
		upstreamConn.Close()
		return
	}

	clientConn, _, err := hijacker.Hijack()
	if err != nil {
		status = http.StatusInternalServerError
		http.Error(w, fmt.Sprintf("Hijack failed: %v", err), status)
		upstreamConn.Close()
		return
	}

	_, err = clientConn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))
	if err != nil {
		status = http.StatusInternalServerError
		clientConn.Close()
		upstreamConn.Close()
		return
	}

	serverCert, err := h.getServerCert(hostname)
	if err != nil {
		status = http.StatusInternalServerError
		logger.Errorf("Failed to generate cert for %s: %v", hostname, err)
		clientConn.Close()
		upstreamConn.Close()
		return
	}

	clientTLS := tls.Server(clientConn, createDownstreamTLSConfig(serverCert))
	if err = clientTLS.Handshake(); err != nil {
		status = http.StatusBadGateway
		logger.Errorf("Downstream TLS handshake failed for %s: %v", hostname, err)
		clientConn.Close()
		upstreamConn.Close()
		return
	}

	relay(clientTLS, upstreamConn)
}

func (h *ProxyHandler) handleHTTP(w http.ResponseWriter, r *http.Request) {
	targetURL := r.URL.String()
	if !strings.HasPrefix(targetURL, "http://") && !strings.HasPrefix(targetURL, "https://") {
		http.Error(w, "Bad Request: URL must include http:// or https://", http.StatusBadRequest)
		return
	}

	if r.URL.Host == "cert.install" {
		w.Header().Add("Content-Type", "application/x-x509-ca-cert")
		w.Write(h.caCert.Raw)
		return
	}

	upstreamReq, err := http.NewRequest(r.Method, targetURL, r.Body)
	if err != nil {
		http.Error(w, fmt.Sprintf("Request error: %v", err), http.StatusInternalServerError)
		return
	}

	upstreamReq.Header = r.Header.Clone()
	for key := range hopByHopHeaders {
		upstreamReq.Header.Del(key)
	}

	upstreamReq.Host = r.URL.Host

	transport := &http.Transport{
		TLSClientConfig: &tls.Config{
			ServerName: r.URL.Hostname(),
		},
	}

	if h.proxyDialContext != nil {
		transport.DialContext = h.proxyDialContext
	}

	client := &http.Client{
		Timeout:   30 * time.Second,
		Transport: transport,
	}

	resp, err := client.Do(upstreamReq)
	if err != nil {
		var urlErr *url.Error
		if errors.As(err, &urlErr) && urlErr.Err != nil {
			http.Error(w, fmt.Sprintf("Bad Gateway: %v", urlErr.Err), http.StatusBadGateway)
			return
		}

		http.Error(w, fmt.Sprintf("Proxy error: %v", err), http.StatusInternalServerError)
		return
	}
	defer resp.Body.Close()

	for key, values := range resp.Header {
		if hopByHopHeaders[key] {
			continue
		}
		for _, value := range values {
			w.Header().Add(key, value)
		}
	}

	w.WriteHeader(resp.StatusCode)
	io.Copy(w, resp.Body)
}
