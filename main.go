package main

import (
	"bufio"
	"compress/gzip"
	"context"
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
	"runtime"
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

type proxyPool struct {
	backends []string
	idx      uint32
}

func (p *proxyPool) next() string {
	if len(p.backends) == 0 {
		return ""
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
				pool.backends = append(pool.backends, rt.Upstreams...)
				h = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					t := pool.next()
					if t == "" {
						http.Error(w, "No upstream", http.StatusBadGateway)
						return
					}
					proxyTo(w, r, t, rt)
				})
			} else {
				h = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					http.NotFound(w, r)
				})
			}
			wrap := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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

func printHelp() {
	fmt.Println(`goserve - Simple Go HTTP File Server

Usage:
  goserve start [--dir DIR] [--addr ADDR] [--log] [--tls-cert CERT] [--tls-key KEY]

Options:
  --dir        Directory to serve HTML from (default: ./web in goserve directory)
  --addr       Address to listen on (default: :8080)
  --log        Log GET requests with duration
  --tls-cert   Path to TLS certificate
  --tls-key    Path to TLS key

Commands:
  start        Start the HTTP server

Examples:
  goserve start --dir ./ --addr :8081 --log`)
}

func main() {
	if len(os.Args) < 2 || os.Args[1] != "start" {
		printHelp()
		return
	}

	var defaultDir string
	if runtime.GOOS == "windows" {
		execPath, err := os.Executable()
		if err != nil {
			log.Fatalf("Failed to get executable path: %v", err)
		}
		execDir := filepath.Dir(execPath)
		defaultDir = filepath.Join(execDir, "web")
	} else {
		defaultDir = "/usr/local/share/goserve/web"
	}

	os.Args = append([]string{os.Args[0]}, os.Args[2:]...)

	dir := flag.String("dir", defaultDir, "Directory to serve HTML from")
	addr := flag.String("addr", ":8080", "Address to listen on")
	logRequests := flag.Bool("log", false, "Log GET requests with duration")
	tlsCert := flag.String("tls-cert", "", "Path to TLS certificate")
	tlsKey := flag.String("tls-key", "", "Path to TLS key")
	flag.Parse()

	if _, err := os.Stat(*dir); os.IsNotExist(err) {
		log.Fatalf("Directory %s does not exist", *dir)
	}

	var (
		handlerValue atomic.Value
		counter      *ipCounter
	)

	buildHandler := func() http.Handler {
		fsHandler := http.FileServer(http.Dir(*dir))
		if *logRequests {
			if counter == nil {
				counter = newIPCounter()
			}
			return logRequestHandler(fsHandler, counter)
		}
		return fsHandler
	}

	handlerValue.Store(buildHandler())

	srv := &http.Server{
		Addr: *addr,
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			handlerValue.Load().(http.Handler).ServeHTTP(w, r)
		}),
	}

	if *tlsCert != "" && *tlsKey != "" { // future feature (soon as it's already in the -help section)
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

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		scanner := bufio.NewScanner(os.Stdin)
		options := []string{"exit", "stop", "reload"}
		for {
			fmt.Print(">>> ")
			if !scanner.Scan() {
				break
			}
			cmd := scanner.Text()
			switch cmd {
			case "exit", "stop":
				fmt.Println("Shutting down...")
				_ = srv.Shutdown(context.TODO())
				os.Exit(0)
			case "help", "-help":
				printHelp()
			case "":
				continue
			case "reload":
				fmt.Println("Reloading Server!")
				if _, err := os.Stat(*dir); os.IsNotExist(err) {
					fmt.Printf("Directory %s does not exist\n", *dir)
					continue
				}
				handlerValue.Store(buildHandler())
			default:
				suggestion := closestOption(cmd, options)
				if suggestion != "" {
					fmt.Printf("Invalid Option. Did you mean: %s?\n", suggestion)
				} else {
					fmt.Println("Invalid Option.")
				}
			}
		}
	}()

	<-stop
	fmt.Println("Received interrupt, shutting down...")
	_ = srv.Shutdown(context.TODO())
	os.Exit(0)
	fmt.Println("Server stopped.")
}

func closestOption(input string, options []string) string {
	minDist := 3
	closest := ""
	for _, opt := range options {
		if d := levenshtein(input, opt); d < minDist {
			minDist = d
			closest = opt
		}
	}
	return closest
}

func levenshtein(a, b string) int {
	la, lb := len(a), len(b)
	if la == 0 {
		return lb
	}
	if lb == 0 {
		return la
	}
	dp := make([][]int, la+1)
	for i := range dp {
		dp[i] = make([]int, lb+1)
	}
	for i := 0; i <= la; i++ {
		dp[i][0] = i
	}
	for j := 0; j <= lb; j++ {
		dp[0][j] = j
	}
	for i := 1; i <= la; i++ {
		for j := 1; j <= lb; j++ {
			cost := 0
			if a[i-1] != b[j-1] {
				cost = 1
			}
			dp[i][j] = min(
				dp[i-1][j]+1,
				dp[i][j-1]+1,
				dp[i-1][j-1]+cost,
			)
		}
	}
	return dp[la][lb]
}

func min(a, b, c int) int {
	if a < b && a < c {
		return a
	}
	if b < c {
		return b
	}
	return c
}
