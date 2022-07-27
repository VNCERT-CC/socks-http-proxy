# socks-http-proxy
Socks proxy to http proxy

# Confirm socks proxy is running
```batch
curl -x socks5://127.0.0.1:1080 https://1.1.1.1/cdn-cgi/trace
```

# Add domains (hostname) in to domains.txt or domains-regex.txt

# Convert socks proxy to http proxy
```batch
socks-http-proxy -l 127.0.0.1:8081 -x "socks5://127.0.0.1:1080?timeout=5m"
```

# Confirm http proxy is running
```batch
curl -x http://127.0.0.1:8081 https://1.1.1.1/cdn-cgi/trace
```
