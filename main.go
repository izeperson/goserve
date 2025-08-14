package main

import (
	"bufio"
	"compress/gzip"
	"crypto/tls"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

type Config struct {
	Listeners []Listener `json:"listeners"`
	Servers   []Server   `json:"servers"`
	Gzip      bool       `json:"gzip"`
	AccessLog string     `json:"access_log"`
	RateLimit *RateCfg   `json:"rate_limit"`
}

type Listener struct {
	Addr    string `json:"addr"`
	TLSCert string `json:"tls_cert"`
	TLSKey  string `json:"tls_key"`
}

type Server struct {
	Hosts  []string `json:"hosts"`
	Routes []Route  `json:"routes"`
}

type Route struct {
	PathPrefix     string            `json:"path_prefix"`
	StripPrefix    bool              `json:"strip_prefix"`
	StaticDir      string            `json:"static_dir"`
	IndexFile      string            `json:"index_file"`
	Upstreams      []string          `json:"upstreams"`
	TimeoutSeconds int               `json:"timeout_seconds"`
	ProxyHeaders   map[string]string `json:"proxy_headers"`
}

type RateCfg struct {
	RequestsPerSecond float64 `json:"rps"`
	Burst             float64 `json:"burst"`
}

type atomicHandler struct{ v atomic.Value }

func (a *atomicHandler) Store(h http.Handler) { a.v.Store(h) }
func (a *atomicHandler) Load() http.Handler   { return a.v.Load().(http.Handler) }
func (a *atomicHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	a.Load().ServeHTTP(w, r)
}

type proxyPool struct {
	backends []*urlTarget
	idx      uint32
}

type urlTarget struct {
	url string
}

func (p *proxyPool) next() *urlTarget {
	if len(p.backends) == 0 {
		return nil
	}
	i := atomic.AddUint32(&p.idx, 1)
	return p.backends[int(i-1)%len(p.backends)]
}

type ipLimiter struct {
	mu   sync.Mutex
	m    map[string]*bucket
	conf RateCfg
}

type bucket struct {
	allow float64
	last  time.Time
}

func newIPLimiter(c RateCfg) *ipLimiter { return &ipLimiter{m: map[string]*bucket{}, conf: c} }

func (l *ipLimiter) allowNow(ip string) bool {
	if l.conf.RequestsPerSecond <= 0 {
		return true
	}
	now := time.Now()
	l.mu.Lock()
	b := l.m[ip]
	if b == nil {
		b = &bucket{allow: l.conf.Burst, last: now}
		l.m[ip] = b
	}
	delta := now.Sub(b.last).Seconds() * l.conf.RequestsPerSecond
	b.allow += delta
	if b.allow > l.conf.Burst {
		b.allow = l.conf.Burst
	}
	b.last = now
	ok := b.allow >= 1
	if ok {
		b.allow -= 1
	}
	l.mu.Unlock()
	return ok
}

type gzipResponseWriter struct {
	h           http.ResponseWriter
	w           *gzip.Writer
	wroteHeader bool
}

func (g *gzipResponseWriter) Header() http.Header { return g.h.Header() }
func (g *gzipResponseWriter) WriteHeader(status int) {
	if g.wroteHeader {
		return
	}
	g.h.Header().Del("Content-Length")
	g.h.WriteHeader(status)
	g.wroteHeader = true
}
func (g *gzipResponseWriter) Write(b []byte) (int, error) {
	if !g.wroteHeader {
		g.WriteHeader(http.StatusOK)
	}
	return g.w.Write(b)
}

func getClientIP(r *http.Request) string {
	if x := r.Header.Get("X-Forwarded-For"); x != "" {
		parts := strings.Split(x, ",")
		return strings.TrimSpace(parts[0])
	}
	ip, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return ip
}

func combinedLog(line string) { log.Print(line) }

func makeAccessLog(next http.Handler, pattern string) http.Handler {
	if pattern == "" {
		return next
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		lrw := &logResponseWriter{ResponseWriter: w, status: 200}
		start := time.Now()
		next.ServeHTTP(lrw, r)
		dur := time.Since(start)
		host := r.Host
		ip := getClientIP(r)
		ua := r.UserAgent()
		uri := r.URL.RequestURI()
		line := fmt.Sprintf("%s - - [%s] \"%s %s %s\" %d %d \"%s\" \"%s\" %dms %s", ip, start.Format("02/Jan/2006:15:04:05 -0700"), r.Method, uri, r.Proto, lrw.status, lrw.bytes, r.Referer(), ua, dur.Milliseconds(), host)
		combinedLog(line)
	})
}

type logResponseWriter struct {
	http.ResponseWriter
	status int
	bytes  int
}

func (l *logResponseWriter) WriteHeader(code int) {
	l.status = code
	l.ResponseWriter.WriteHeader(code)
}
func (l *logResponseWriter) Write(b []byte) (int, error) {
	n, e := l.ResponseWriter.Write(b)
	l.bytes += n
	return n, e
}

func gzipMiddleware(enabled bool, next http.Handler) http.Handler {
	if !enabled {
		return next
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.Contains(r.Header.Get("Accept-Encoding"), "gzip") {
			next.ServeHTTP(w, r)
			return
		}
		w.Header().Set("Content-Encoding", "gzip")
		gz := gzip.NewWriter(w)
		defer gz.Close()
		grw := &gzipResponseWriter{h: w, w: gz}
		next.ServeHTTP(grw, r)
	})
}

func rateLimitMiddleware(l *ipLimiter, next http.Handler) http.Handler {
	if l == nil {
		return next
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ip := getClientIP(r)
		if !l.allowNow(ip) {
			http.Error(w, "Too Many Requests", http.StatusTooManyRequests)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func hostMatch(hosts []string, h string) bool {
	if len(hosts) == 0 {
		return true
	}
	h = strings.ToLower(h)
	for _, v := range hosts {
		if strings.EqualFold(v, h) {
			return true
		}
	}
	return false
}

func pathHasPrefix(pfx, p string) bool {
	if pfx == "/" || pfx == "" {
		return true
	}
	return strings.HasPrefix(p, pfx)
}

func buildHandler(cfg *Config) http.Handler {
	mux := http.NewServeMux()
	for _, srv := range cfg.Servers {
		for _, rt := range srv.Routes {
			pfx := rt.PathPrefix
			if pfx == "" {
				pfx = "/"
			}
			var h http.Handler
			if rt.StaticDir != "" {
				dir := http.Dir(rt.StaticDir)
				fs := http.FileServer(dir)
				if rt.IndexFile != "" {
					fs = withIndex(fs, string(dir), rt.IndexFile)
				}
				if rt.StripPrefix && pfx != "/" {
					h = http.StripPrefix(pfx, fs)
				} else {
					h = fs
				}
			} else if len(rt.Upstreams) > 0 {
				pool := &proxyPool{}
				for _, u := range rt.Upstreams {
					pool.backends = append(pool.backends, &urlTarget{url: u})
				}
				h = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					t := pool.next()
					if t == nil {
						http.Error(w, "No upstream", 502)
						return
					}
					proxyTo(w, r, t.url, rt)
				})
			} else {
				h = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { http.NotFound(w, r) })
			}
			wrap := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if !hostMatch(srv.Hosts, r.Host) {
					http.NotFound(w, r)
					return
				}
				if !pathHasPrefix(pfx, r.URL.Path) {
					http.NotFound(w, r)
					return
				}
				h.ServeHTTP(w, r)
			})
			mux.Handle(pfx, wrap)
		}
	}
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "ok") })
	h := http.Handler(mux)
	if cfg.Gzip {
		h = gzipMiddleware(true, h)
	}
	if cfg.RateLimit != nil {
		h = rateLimitMiddleware(newIPLimiter(*cfg.RateLimit), h)
	}
	if cfg.AccessLog != "-" {
		h = makeAccessLog(h, cfg.AccessLog)
	} else {
		h = makeAccessLog(h, "-")
	}
	return h
}

func withIndex(next http.Handler, base, index string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p := r.URL.Path
		full := filepath.Join(base, p)
		if st, err := os.Stat(full); err == nil && st.IsDir() {
			fp := filepath.Join(full, index)
			if _, err := os.Stat(fp); err == nil {
				http.ServeFile(w, r, fp)
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}

func proxyTo(w http.ResponseWriter, r *http.Request, target string, rt Route) {
	if rt.StripPrefix && rt.PathPrefix != "/" && rt.PathPrefix != "" {
		r.URL.Path = strings.TrimPrefix(r.URL.Path, rt.PathPrefix)
		if !strings.HasPrefix(r.URL.Path, "/") {
			r.URL.Path = "/" + r.URL.Path
		}
	}

	parsedURL, err := url.Parse(target)
	if err != nil {
		http.Error(w, "Invalid upstream URL", http.StatusInternalServerError)
		return
	}

	p := httputil.NewSingleHostReverseProxy(parsedURL)
	if rt.TimeoutSeconds > 0 {
		d := time.Duration(rt.TimeoutSeconds) * time.Second
		p.Transport = &http.Transport{
			Proxy:               http.ProxyFromEnvironment,
			DialContext:         (&net.Dialer{Timeout: d}).DialContext,
			TLSHandshakeTimeout: d,
		}
	}
	orig := p.Director
	p.Director = func(req *http.Request) {
		orig(req)
		for k, v := range rt.ProxyHeaders {
			req.Header.Set(k, v)
		}
	}
	p.ErrorHandler = func(rw http.ResponseWriter, req *http.Request, err error) {
		http.Error(rw, "Bad Gateway", http.StatusBadGateway)
	}
	p.ServeHTTP(w, r)
}

func parseConfig(p string) (*Config, error) {
	if p == "" {
		return defaultConfig(), nil
	}
	b, err := os.ReadFile(p)
	if err != nil {
		return nil, err
	}
	var cfg Config
	if err := json.Unmarshal(b, &cfg); err != nil {
		return nil, err
	}
	return &cfg, nil
}

func defaultConfig() *Config {
	return &Config{
		Listeners: []Listener{{Addr: ":8080"}},
		Servers: []Server{{
			Hosts:  []string{},
			Routes: []Route{{PathPrefix: "/", StaticDir: ".", IndexFile: "index.html"}},
		}},
		Gzip:      true,
		AccessLog: "combined",
	}
}

func serve(cfg *Config) ([]*http.Server, error) {
	var servers []*http.Server
	baseHandler := buildHandler(cfg)
	for _, lst := range cfg.Listeners {
		h := baseHandler
		ah := &atomicHandler{}
		ah.Store(h)
		srv := &http.Server{Handler: ah}
		ln, err := net.Listen("tcp", lst.Addr)
		if err != nil {
			return nil, err
		}
		if lst.TLSCert != "" && lst.TLSKey != "" {
			cert, err := tls.LoadX509KeyPair(lst.TLSCert, lst.TLSKey)
			if err != nil {
				return nil, err
			}
			tlsCfg := &tls.Config{Certificates: []tls.Certificate{cert}, NextProtos: []string{"h2", "http/1.1"}}
			ln = tls.NewListener(ln, tlsCfg)
		}
		servers = append(servers, srv)
		go func(s *http.Server, l net.Listener) { _ = s.Serve(l) }(srv, ln)
	}
	return servers, nil
}

func reload(ah []*atomicHandler, path string) error { return nil }

type ipCounter struct {
	mu    sync.Mutex
	count map[string]int
}

func newIPCounter() *ipCounter {
	return &ipCounter{count: make(map[string]int)}
}

func (c *ipCounter) increment(ip string) int {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.count[ip]++
	return c.count[ip]
}

func logRequestHandler(next http.Handler, counter *ipCounter) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		next.ServeHTTP(w, r)
		if r.Method == "GET" {
			duration := time.Since(start)
			ip := r.RemoteAddr
			cnt := counter.increment(ip)
			fmt.Printf("\033[32m[GET]\033[0m %s: %dms, %d\n", ip, duration.Milliseconds(), cnt)
		}
	})
}

func main() {
	dir := flag.String("dir", "./html", "Directory to serve HTML from")
	addr := flag.String("addr", ":8080", "Address to listen on")
	logRequests := flag.Bool("log", false, "Log GET requests with duration")
	tlsCert := flag.String("tls-cert", "", "Path to TLS certificate")
	tlsKey := flag.String("tls-key", "", "Path to TLS key")
	flag.Parse()

	if _, err := os.Stat(*dir); os.IsNotExist(err) {
		log.Fatalf("Directory %s does not exist", *dir)
	}

	fsHandler := http.FileServer(http.Dir(*dir))
	var handler http.Handler = fsHandler

	if *logRequests {
		counter := newIPCounter()
		handler = logRequestHandler(fsHandler, counter)
	}

	srv := &http.Server{
		Addr:    *addr,
		Handler: handler,
	}

	if *tlsCert != "" && *tlsKey != "" {
		fmt.Printf("Serving %s on %s (TLS)\n", *dir, *addr)
		go func() {
			if err := srv.ListenAndServeTLS(*tlsCert, *tlsKey); err != nil && err != http.ErrServerClosed {
				log.Fatal(err)
			}
		}()
	} else {
		fmt.Printf("Serving %s on %s\n", *dir, *addr)
		go func() {
			if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
				log.Fatal(err)
			}
		}()
	}
	// Graceful shutdown logic
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		scanner := bufio.NewScanner(os.Stdin)
		for {
			fmt.Print(">>> ")
			if !scanner.Scan() {
				break
			}
			cmd := scanner.Text()
			if cmd == "exit" || cmd == "stop" {
				fmt.Println("Shutting down...")
				_ = srv.Close()
				os.Exit(0)
			}
			if cmd == "reload" {
				fmt.Println("Reloading Server!")
				if _, err := os.Stat(*dir); os.IsNotExist(err) {
					fmt.Printf("Directory %s does not exist\n", *dir)
					continue
				}
				newHandler := http.FileServer(http.Dir(*dir))
				if *logRequests {
					counter := newIPCounter()
					newHandler = logRequestHandler(newHandler, counter)
				}
				srv.Handler = newHandler
			}
		}
	}()

	<-stop
	fmt.Println("Received interrupt, shutting down...")
	_ = srv.Close()
	fmt.Println("Server stopped.")
}
