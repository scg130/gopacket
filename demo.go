package main

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
)

// 目标服务器的 URL
const targetURL = "https://example.com" // 请替换为目标服务器的地址

// 处理客户端请求，解密并转发到目标服务器
func handleHTTPSRequest(w http.ResponseWriter, r *http.Request) {
	// 打印请求信息（可选）
	fmt.Printf("Intercepted request: %s %s\n", r.Method, r.URL)

	// 配置目标服务器的 URL
	proxyURL, err := url.Parse(targetURL)
	if err != nil {
		log.Fatalf("Error parsing proxy URL: %v", err)
		http.Error(w, "Proxy error", http.StatusInternalServerError)
		return
	}

	// 创建反向代理
	proxy := httputil.NewSingleHostReverseProxy(proxyURL)

	// 转发请求
	proxy.ServeHTTP(w, r)
}

// 生成TLS配置
func generateTLSConfig() *tls.Config {
	// 加载自签名证书
	cert, err := tls.LoadX509KeyPair("cert.pem", "key.pem") // 加载你生成的证书和私钥
	if err != nil {
		log.Fatalf("Error loading X509 key pair: %v", err)
	}

	// 创建一个空的证书池，用于信任自签名证书
	certPool := x509.NewCertPool()
	certBytes, err := os.ReadFile("cert.pem") // 读取证书文件
	if err != nil {
		log.Fatalf("Error reading certificate file: %v", err)
	}

	certPool.AppendCertsFromPEM(certBytes)

	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		ClientCAs:    certPool,
		ClientAuth:   tls.RequireAnyClientCert, // 允许任何客户端证书
		MinVersion:   tls.VersionTLS13,         // 设置最低的 TLS 版本
	}
}

// 启动HTTPS代理服务器
func startHTTPSProxy() {
	// 监听指定端口（通常为443，HTTPS默认端口）
	ln, err := net.Listen("tcp", ":8443")
	if err != nil {
		log.Fatalf("Error starting server: %v", err)
	}
	defer ln.Close()

	// 设置 TLS 配置
	tlsConfig := generateTLSConfig()

	// 通过TLS监听客户端连接
	tlsListener := tls.NewListener(ln, tlsConfig)

	// 处理HTTPS请求
	http.HandleFunc("/", handleHTTPSRequest)

	// 启动服务器并处理连接
	log.Println("HTTPS Proxy server listening on :8443")
	if err := http.Serve(tlsListener, nil); err != nil {
		log.Fatalf("Error serving: %v", err)
	}
}

func main() {
	// 启动 HTTPS 代理服务器
	startHTTPSProxy()
}
