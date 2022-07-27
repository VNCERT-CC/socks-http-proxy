package main

import (
	"bytes"
	"flag"
	"io/ioutil"
	"log"
	"net"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/valyala/fasthttp"
	"h12.io/socks"
)

var httpClientTimeout = 15 * time.Second
var dialTimeout = 7 * time.Second
var socksDialFunc func(string, string) (net.Conn, error)

var localDialFunc = (&net.Dialer{
	Timeout:   dialTimeout,
	DualStack: true,
}).Dial

var httpClientLocal = &fasthttp.Client{
	ReadTimeout:         30 * time.Second,
	MaxConnsPerHost:     233,
	MaxIdleConnDuration: 15 * time.Minute,
	ReadBufferSize:      1024 * 8,
	Dial: func(addr string) (net.Conn, error) {
		// no suitable address found => ipv6 can not dial to ipv4,..
		hostname, port, err := net.SplitHostPort(addr)
		if err != nil {
			if err1, ok := err.(*net.AddrError); ok && strings.Contains(err1.Err, "missing port") {
				hostname, port, err = net.SplitHostPort(strings.TrimRight(addr, ":") + ":80")
			}
			if err != nil {
				return nil, err
			}
		}
		if port == "" || port == ":" {
			port = "80"
		}
		return fasthttp.DialDualStackTimeout("["+hostname+"]:"+port, dialTimeout)
	},
}

var httpClientSocks = &fasthttp.Client{
	ReadTimeout:         30 * time.Second,
	MaxConnsPerHost:     233,
	MaxIdleConnDuration: 15 * time.Minute,
	ReadBufferSize:      1024 * 8,
	Dial: func(addr string) (net.Conn, error) {
		// no suitable address found => ipv6 can not dial to ipv4,..
		hostname, port, err := net.SplitHostPort(addr)
		if err != nil {
			if err1, ok := err.(*net.AddrError); ok && strings.Contains(err1.Err, "missing port") {
				hostname, port, err = net.SplitHostPort(strings.TrimRight(addr, ":") + ":80")
			}
			if err != nil {
				return nil, err
			}
		}
		if port == "" || port == ":" {
			port = "80"
		}
		return socksDialFunc("tcp", "["+hostname+"]:"+port)
	},
}

func copy2(dst net.Conn, src net.Conn) {
	defer func() {
		time.Sleep(time.Second)
		dst.Close()
		src.Close()
	}()
	buf := make([]byte, 4096)
	for {
		n, err := src.Read(buf)
		if err != nil {
			// log.Println(`Read err:`, err)
			return
		}
		// log.Println(src.RemoteAddr().String(), `=>`, dst.RemoteAddr().String(), `:`, len(buf[:n]))
		_, err = dst.Write(buf[:n])
		if err != nil {
			// log.Println(`Write errL`, err)
			return
		}
	}
}

func httpsHandler(ctx *fasthttp.RequestCtx, remoteAddr string, isMustProxify bool) error {
	if ctx.Hijacked() {
		return nil
	}
	var r net.Conn
	if isMustProxify {
		var err error
		r, err = socksDialFunc("tcp", remoteAddr)
		if err != nil {
			return err
		}
	} else {
		var err error
		r, err = localDialFunc("tcp", remoteAddr)
		if err != nil {
			return err
		}
	}
	ctx.SetStatusCode(fasthttp.StatusOK)
	ctx.Response.Header.Set("Connection", "keep-alive")
	ctx.Response.Header.Set("Keep-Alive", "timeout=120, max=5")
	ctx.Hijack(func(clientConn net.Conn) {
		go copy2(r, clientConn)
		copy2(clientConn, r)
	})
	return nil
}

func requestHandler(ctx *fasthttp.RequestCtx) {
	// Some library must set header: Connection: keep-alive
	// ctx.Response.Header.Del("Connection")
	// ctx.Response.ConnectionClose() // ==> false

	// log.Println(string(ctx.Path()), string(ctx.Host()), ctx.String(), "\r\n\r\n", ctx.Request.String())

	host := string(ctx.Host())
	if len(host) < 1 {
		ctx.SetStatusCode(fasthttp.StatusBadRequest)
		log.Println("Reject: Empty host")
		return
	}

	hostname, port, err := net.SplitHostPort(host)
	if err != nil {
		if err1, ok := err.(*net.AddrError); ok && strings.Contains(err1.Err, "missing port") {
			hostname, port, err = net.SplitHostPort(host + ":443")
		}
		if err != nil {
			ctx.SetStatusCode(fasthttp.StatusBadRequest)
			log.Println("Reject: Invalid host", host, err)
			return
		}
	}

	isMustProxify := mustProxify(hostname)

	// https connecttion
	if bytes.Equal(ctx.Method(), []byte("CONNECT")) {
		err = httpsHandler(ctx, `[`+hostname+`]:`+port, isMustProxify)
		if err != nil {
			ctx.SetStatusCode(fasthttp.StatusInternalServerError)
			log.Println("httpsHandler:", host, err)
		}
		return
	}

	if isMustProxify {
		err = httpClientSocks.DoTimeout(&ctx.Request, &ctx.Response, httpClientTimeout)
	} else {
		err = httpClientLocal.DoTimeout(&ctx.Request, &ctx.Response, httpClientTimeout)
	}

	if err != nil {
		ctx.SetStatusCode(fasthttp.StatusInternalServerError)
		log.Println("httpHandler:", host, err)
	}
}

// Domains
var domainList = flag.String("d", "domains.txt", "Domains List File")
var domainRegexList = flag.String("r", "domains-regex.txt", "Domains Regex List File")

var domainProxiesCache = map[string]bool{}
var domainProxiesCacheLock sync.RWMutex
var domainsRegex []*regexp.Regexp
var lineRegex = regexp.MustCompile(`[\r\n]+`)

func parseDomains() bool {
	if len(*domainList) > 0 {
		c, err := ioutil.ReadFile(*domainList)
		if err == nil {
			lines := lineRegex.Split(string(c), -1)
			for _, line := range lines {
				line = strings.Trim(line, "\r\n\t ")
				if len(line) < 1 || line[0] == '#' {
					continue
				}
				domainProxiesCacheLock.Lock()
				domainProxiesCache[line] = true
				domainProxiesCacheLock.Unlock()
			}
		} else {
			log.Println(err)
		}
	}
	if len(*domainRegexList) > 0 {
		c, err := ioutil.ReadFile(*domainRegexList)
		if err == nil {
			lines := lineRegex.Split(string(c), -1)
			for _, line := range lines {
				line = strings.Trim(line, "\r\n\t ")
				if len(line) < 1 || line[0] == '#' {
					continue
				}
				domainsRegex = append(domainsRegex, regexp.MustCompile(line))
			}
		} else {
			log.Println(err)
		}
	}
	if len(domainsRegex) < 1 && len(domainProxiesCache) < 1 {
		log.Println("No domains to proxy? Please specify a domain name in", *domainList, "or", *domainRegexList)
		return false
	}
	return true
}

// OK, no lock need here
func mustProxify(hostname string) bool {
	domainProxiesCacheLock.RLock()
	b, ok := domainProxiesCache[hostname]
	domainProxiesCacheLock.RUnlock()
	if ok {
		return b
	}
	b = false
	for _, re := range domainsRegex {
		b = re.MatchString(hostname)
		if b {
			break
		}
	}
	domainProxiesCacheLock.Lock()
	domainProxiesCache[hostname] = b
	domainProxiesCacheLock.Unlock()
	log.Println("Proxify:", hostname, b)
	return b
}

var listen = flag.String(`l`, `:8081`, `Listen address. Eg: :8443; unix:/tmp/proxy.sock`)
var socksURI = flag.String(`x`, `socks5://127.0.0.1:1080?timeout=5m`, `Socks proxy URI`)

func main() {
	flag.Parse()
	socksDialFunc = socks.Dial(*socksURI)

	if !parseDomains() {
		return
	}

	// Server
	var err error
	var ln net.Listener
	if strings.HasPrefix(*listen, `unix:`) {
		unixFile := (*listen)[5:]
		os.Remove(unixFile)
		ln, err = net.Listen(`unix`, unixFile)
		os.Chmod(unixFile, os.ModePerm)
		log.Println(`Listening:`, unixFile)
	} else {
		ln, err = net.Listen(`tcp`, *listen)
		log.Println(`Listening:`, ln.Addr().String())
	}
	if err != nil {
		log.Panicln(err)
	}
	srv := &fasthttp.Server{
		// ErrorHandler: nil,
		Handler:               requestHandler,
		NoDefaultServerHeader: true, // Don't send Server: fasthttp
		// Name: "nginx",  // Send Server header
		ReadBufferSize:                2 * 4096, // Make sure these are big enough.
		WriteBufferSize:               4096,
		ReadTimeout:                   5 * time.Second,
		WriteTimeout:                  time.Second,
		IdleTimeout:                   time.Minute, // This can be long for keep-alive connections.
		DisableHeaderNamesNormalizing: false,       // If you're not going to look at headers or know the casing you can set this.
		// NoDefaultContentType: true, // Don't send Content-Type: text/plain if no Content-Type is set manually.
		MaxRequestBodySize: 200 * 1024 * 1024, // 200MB
		DisableKeepalive:   false,
		KeepHijackedConns:  false,
		// NoDefaultDate: len(*staticDir) == 0,
		ReduceMemoryUsage: true,
		TCPKeepalive:      true,
		// TCPKeepalivePeriod: 10 * time.Second,
		// MaxRequestsPerConn: 1000,
		// MaxConnsPerIP: 20,
	}
	log.Panicln(srv.Serve(ln))
}
