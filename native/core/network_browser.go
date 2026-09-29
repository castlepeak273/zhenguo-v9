package core

import (
	"crypto/tls"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	fhttp "github.com/bogdanfinn/fhttp"
	tlsclient "github.com/bogdanfinn/tls-client"
	"github.com/bogdanfinn/tls-client/profiles"
)

const huangguoBrowserProfile = "Chrome 150"

type browserHTTPClient interface {
	Do(*fhttp.Request) (*fhttp.Response, error)
	CloseIdleConnections()
}

type huangguoBrowserTransport struct {
	base      http.RoundTripper
	router    *proxyRouter
	hosts     map[string]bool
	insecure  bool
	record    func(diagnosticEvent)
	mu        sync.Mutex
	clients   map[string]browserHTTPClient
	newClient func(string, bool) (browserHTTPClient, error)
}

func newHuangguoBrowserTransport(base http.RoundTripper, downloader *Downloader) *huangguoBrowserTransport {
	configured, _ := url.Parse(downloader.providerBaseURL(sourceHuangguoVideo))
	transport := &huangguoBrowserTransport{
		base: base, router: downloader.proxyRouter, hosts: browserTransportHosts(configured.Host),
		insecure: downloader.cfg.InsecureTLS, record: downloader.recordDiagnostic,
		clients: make(map[string]browserHTTPClient),
	}
	transport.newClient = transport.createClient
	return transport
}

func browserTransportHosts(huangguoVideoHost string) map[string]bool {
	hosts := map[string]bool{"huangguo.video": true}
	if huangguoVideoHost != "" {
		hosts[strings.ToLower(huangguoVideoHost)] = true
	}
	for _, spec := range duanjuProviderCatalog {
		if !spec.Browser {
			continue
		}
		if parsed, err := url.Parse(spec.Base); err == nil && parsed.Host != "" {
			hosts[strings.ToLower(parsed.Host)] = true
		}
	}
	return hosts
}

func (transport *huangguoBrowserTransport) matches(request *http.Request) bool {
	// 这里不能限制请求方法。野果等站源的接口用的是 POST
	// (例如 https://www.yeguodj.com/api.php/api/theater/exploreList)，
	// 只放行 GET/HEAD 会让这些请求绕过本通道、走默认 TCP，被 RST。
	if request.URL.Scheme != "http" && request.URL.Scheme != "https" {
		return false
	}
	if transport.hosts[strings.ToLower(request.URL.Host)] || transport.hosts[strings.ToLower(request.URL.Hostname())] {
		return true
	}
	// 其余已登记站源（红果、黄豆、剧果、野果、帝果、黄果系…）同样走
	// 「浏览器指纹 + HTTP/3 竞速」。
	//
	// 为什么必须覆盖全部站源：部分线路只对 TCP 的 SNI 做阻断（一发
	// ClientHello 就被 RST），而同一域名的 QUIC(UDP 443) 不受影响。
	// 实测（同一网络，关闭 / 开启 HTTP/3）：
	//     帝果 www.dsd.com.se      reset  ->  200 HTTP/3.0
	//     野果 yeguodj.com         reset  ->  200 HTTP/3.0
	//     黄果AI thu.ediayikma.cc  reset  ->  200 HTTP/3.0
	//     黄豆 tideember.cc        reset  ->  200 HTTP/1.1
	// WithProtocolRacing() 会并行竞速并记住每个域名可用的协议，
	// 所以对只支持 HTTP/2 的域名（如 analyze.buxefaex.cc）也会自动回退。
	return providerSourceForURL(request.URL.String()) != ""
}

// tcpOnlyHosts: 实测「走 HTTP/3 反而更差」的域名，强制走 TCP。
//
// 背景：HTTP/3 竞速对握手失败的域名要等满 tls-client 的 10 秒上限才返回，
// 再乘上 fetchProviderText 的 3 次重试就是 30 秒，直接吃掉野果发现的 25 秒预算。
//
//	ygdj7.com            线路发现页。HTTP/3 先返回 502、成功也要 5.8s；TCP 只要 0.4-1.3s
//	buxefaex.cc          野果入口。HTTP/3 全部超时；TCP 实测 2.1-3.6s 就能成
//	fzchosdi.cc          ygdj7.com 发现的 4 条线路都在这个域名下，
//	                     走 HTTP/3 每条白等 10s，4 条 40s，必然撑爆预算
//	ygrwdsgt.cc          备用线路。HTTP/3 直接超时
//
// 注意：这里只放「已实测 HTTP/3 更差」的域名，其余一律保持 HTTP/3 竞速 ——
// 部分线路只封 TCP 的 SNI，必须靠 QUIC 才能通：
//
//	ediayikma.cc(黄果) / dsd.com.se(帝果) / yeguodj.com(野果 API) / tideember.cc(黄豆)
//
// 尤其 yeguodj.com 是野果接口域名，走 TCP 会 connection reset，绝不能加进来。
var tcpOnlyHosts = []string{
	"ygdj7.com",
	"buxefaex.cc",
	"fzchosdi.cc",
	"ygrwdsgt.cc",
}

func tcpOnlyHost(host string) bool {
	host = strings.ToLower(strings.TrimSpace(host))
	if host == "" {
		return false
	}
	for _, base := range tcpOnlyHosts {
		if host == base || strings.HasSuffix(host, "."+base) {
			return true
		}
	}
	return false
}

func (transport *huangguoBrowserTransport) createClient(proxy string, racing bool) (browserHTTPClient, error) {
	idleTimeout := 90 * time.Second
	options := []tlsclient.HttpClientOption{
		tlsclient.WithClientProfile(profiles.Chrome_150),
		tlsclient.WithRandomTLSExtensionOrder(),
		tlsclient.WithNotFollowRedirects(),
		tlsclient.WithTimeoutSeconds(45),
		tlsclient.WithProxyUrl(proxy),
		tlsclient.WithCookieJar(tlsclient.NewCookieJar()),
		tlsclient.WithTransportOptions(&tlsclient.TransportOptions{
			IdleConnTimeout: &idleTimeout, MaxIdleConns: 8, MaxIdleConnsPerHost: 4,
			MaxResponseHeaderBytes: 1 << 20,
		}),
	}
	if racing {
		// HTTP/3(QUIC) 与 HTTP/2 并行竞速，自动记住每个域名可用的协议。
		// 部分线路只封 TCP 的 SNI，QUIC(UDP 443) 不受影响，必须靠它才能通。
		options = append(options, tlsclient.WithProtocolRacing())
	} else {
		// 该域名实测走 HTTP/3 更差（502 / 握手失败 / 超时），强制走 TCP。
		options = append(options, tlsclient.WithDisableHttp3())
	}
	if transport.insecure {
		options = append(options, tlsclient.WithInsecureSkipVerify())
	}
	return tlsclient.NewHttpClient(tlsclient.NewNoopLogger(), options...)
}

func (transport *huangguoBrowserTransport) client(request *http.Request) (browserHTTPClient, error) {
	transport.mu.Lock()
	defer transport.mu.Unlock()
	proxy, err := transport.router.proxy(request)
	if err != nil {
		return nil, err
	}
	proxyURL := ""
	if proxy != nil {
		proxyURL = proxy.String()
	}
	racing := !tcpOnlyHost(request.URL.Hostname())
	// 缓存键带上协议模式：同一域名不会因为先来后到而复用到错误的客户端。
	mode := "|h3"
	if !racing {
		mode = "|tcp"
	}
	key := request.URL.Scheme + "://" + strings.ToLower(request.URL.Host) + "|" + proxyURL + mode
	if client := transport.clients[key]; client != nil {
		return client, nil
	}
	client, err := transport.newClient(proxyURL, racing)
	if err != nil {
		return nil, err
	}
	if len(transport.clients) >= 8 {
		for key, old := range transport.clients {
			old.CloseIdleConnections()
			delete(transport.clients, key)
			break
		}
	}
	transport.clients[key] = client
	return client, nil
}

func huangguoBrowserHeaders(request *http.Request) fhttp.Header {
	headers := fhttp.Header{
		"sec-ch-ua":                 {`"Chromium";v="150", "Google Chrome";v="150", "Not_A Brand";v="24"`},
		"sec-ch-ua-mobile":          {"?0"},
		"sec-ch-ua-platform":        {`"macOS"`},
		"upgrade-insecure-requests": {"1"},
		"user-agent":                {"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/150.0.0.0 Safari/537.36"},
		"accept":                    {"text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8"},
		"sec-fetch-site":            {"same-origin"},
		"sec-fetch-mode":            {"navigate"},
		"sec-fetch-user":            {"?1"},
		"sec-fetch-dest":            {"document"},
		"accept-language":           {"zh-CN,zh;q=0.9"},
		fhttp.HeaderOrderKey:        {"sec-ch-ua", "sec-ch-ua-mobile", "sec-ch-ua-platform", "upgrade-insecure-requests", "user-agent", "accept", "sec-fetch-site", "sec-fetch-mode", "sec-fetch-user", "sec-fetch-dest", "referer", "accept-encoding", "accept-language", "cookie"},
	}
	if mode := request.Header.Get("Sec-Fetch-Mode"); mode != "" && mode != "navigate" {
		headers["accept"] = []string{firstNonEmpty(request.Header.Get("Accept"), "*/*")}
		headers["sec-fetch-mode"] = []string{mode}
		headers["sec-fetch-dest"] = []string{firstNonEmpty(request.Header.Get("Sec-Fetch-Dest"), "empty")}
		delete(headers, "upgrade-insecure-requests")
		delete(headers, "sec-fetch-user")
	}
	for key, values := range request.Header {
		lower := strings.ToLower(key)
		if _, fixed := headers[lower]; fixed || lower == "host" || lower == "connection" {
			continue
		}
		headers[lower] = append([]string(nil), values...)
	}
	if referer := request.Header.Get("Referer"); referer == "" {
		headers["sec-fetch-site"] = []string{"none"}
	} else if parsed, err := url.Parse(referer); err == nil && !strings.EqualFold(parsed.Host, request.URL.Host) {
		headers["sec-fetch-site"] = []string{"cross-site"}
	}
	return headers
}

func standardBrowserHeaders(headers fhttp.Header) http.Header {
	result := make(http.Header, len(headers))
	for key, values := range headers {
		result[http.CanonicalHeaderKey(key)] = append([]string(nil), values...)
	}
	return result
}

func (transport *huangguoBrowserTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	if !transport.matches(request) {
		return transport.base.RoundTrip(request)
	}
	client, err := transport.client(request)
	if err != nil {
		return nil, fmt.Errorf("黄果浏览器客户端初始化失败：%w", publicError(err))
	}
	upstream, err := fhttp.NewRequestWithContext(request.Context(), request.Method, request.URL.String(), request.Body)
	if err != nil {
		return nil, err
	}
	upstream.Header = huangguoBrowserHeaders(request)
	upstream.Host = request.Host
	upstream.ContentLength = request.ContentLength
	upstream.GetBody = request.GetBody
	response, err := client.Do(upstream)
	if err != nil {
		if response != nil && response.Body != nil {
			response.Body.Close()
		}
		return nil, publicError(err)
	}
	result := &http.Response{
		Status: response.Status, StatusCode: response.StatusCode,
		Proto: response.Proto, ProtoMajor: response.ProtoMajor, ProtoMinor: response.ProtoMinor,
		Header: standardBrowserHeaders(response.Header), Body: response.Body,
		ContentLength: response.ContentLength, TransferEncoding: response.TransferEncoding,
		Close: response.Close, Uncompressed: response.Uncompressed,
		Trailer: standardBrowserHeaders(response.Trailer), Request: request,
	}
	if state := response.TLS; state != nil {
		result.TLS = &tls.ConnectionState{Version: state.Version, HandshakeComplete: state.HandshakeComplete,
			DidResume: state.DidResume, CipherSuite: state.CipherSuite, NegotiatedProtocol: state.NegotiatedProtocol,
			ServerName: state.ServerName, PeerCertificates: state.PeerCertificates, VerifiedChains: state.VerifiedChains}
	}
	if transport.record != nil {
		level := "info"
		if result.StatusCode >= 400 || strings.EqualFold(result.Header.Get("Cf-Mitigated"), "challenge") {
			level = "warning"
		}
		transport.record(diagnosticEvent{Event: "network.browser_request", Level: level, Source: sourceHuangguoVideo,
			Host: request.URL.Hostname(), HTTPStatus: result.StatusCode, Client: huangguoBrowserProfile,
			Protocol: result.Proto, CFRay: truncate(result.Header.Get("Cf-Ray"), 128),
			ResponseType: truncate(result.Header.Get("Content-Type"), 128), Message: "黄果浏览器指纹请求完成"})
	}
	return result, nil
}

func (transport *huangguoBrowserTransport) CloseIdleConnections() {
	transport.mu.Lock()
	for key, client := range transport.clients {
		client.CloseIdleConnections()
		delete(transport.clients, key)
	}
	transport.mu.Unlock()
	if closer, ok := transport.base.(interface{ CloseIdleConnections() }); ok {
		closer.CloseIdleConnections()
	}
}
