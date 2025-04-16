package catch

import (
	"errors"
	"net"
	"net/http"
	"strings"
)

// RequestForwardedHostProtoMiddleware updates request host and protocol from forwarded headers
func RequestForwardedHostProtoMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r.Host = RequestHost(r)
		r.URL.Scheme = RequestProto(r)
		r.RemoteAddr = RealIPFromRequest(r)
		next.ServeHTTP(w, r)
	})
}

// RequestHost returns the host from forwarded headers or fallback to request host
func RequestHost(r *http.Request) (host string) {
	// Non-standard but most popular header
	host = r.Header.Get("X-Forwarded-Host")
	if host != "" {
		return
	}
	// RFC 7239 standard header
	host = r.Header.Get("Forwarded")
	_, _, host = parseForwarded(host)
	if host != "" {
		return
	}
	// Fallback to request host
	host = r.Host
	return
}

// RequestProto returns the protocol from forwarded headers or fallback to request scheme
func RequestProto(r *http.Request) (proto string) {
	// Non-standard but most popular header
	proto = r.Header.Get("X-Forwarded-Proto")
	if proto != "" {
		return
	}
	// RFC 7239 standard header
	host := r.Header.Get("Forwarded")
	_, proto, _ = parseForwarded(host)
	if proto != "" {
		return
	}
	// Fallback to request scheme
	proto = r.URL.Scheme
	if proto != "" {
		return
	}

	proto = "https"
	return
}

// parseForwarded parses RFC 7239 Forwarded header values
func parseForwarded(forwarded string) (addr, proto, host string) {
	if forwarded == "" {
		return
	}
	for _, forwardedPair := range strings.Split(forwarded, ";") {
		if tv := strings.SplitN(forwardedPair, "=", 2); len(tv) == 2 {
			token, value := tv[0], tv[1]
			token = strings.TrimSpace(token)
			value = strings.TrimSpace(strings.Trim(value, `"`))
			switch strings.ToLower(token) {
			case "for":
				addr = value
			case "proto":
				proto = value
			case "host":
				host = value
			}
		}
	}
	return
}

var cidrs []*net.IPNet

func init() {
	maxCidrBlocks := []string{
		"127.0.0.1/8",    // localhost
		"10.0.0.0/8",     // 24-bit block
		"172.16.0.0/12",  // 20-bit block
		"192.168.0.0/16", // 16-bit block
		"169.254.0.0/16", // link local address
		"::1/128",        // localhost IPv6
		"fc00::/7",       // unique local address IPv6
		"fe80::/10",      // link local address IPv6
	}

	cidrs = make([]*net.IPNet, len(maxCidrBlocks))
	for i, maxCidrBlock := range maxCidrBlocks {
		_, cidr, _ := net.ParseCIDR(maxCidrBlock)
		cidrs[i] = cidr
	}
}

// isPrivateAddress checks if an IP address is in private ranges
func isPrivateAddress(address string) (bool, error) {
	ipAddress := net.ParseIP(address)
	if ipAddress == nil {
		return false, errors.New("address is not valid")
	}

	for i := range cidrs {
		if cidrs[i].Contains(ipAddress) {
			return true, nil
		}
	}

	return false, nil
}

// RealIPFromRequest returns the real client IP from request headers
func RealIPFromRequest(r *http.Request) string {
	// Fetch header values
	xRealIP := r.Header.Get("X-Real-Ip")
	xForwardedFor := r.Header.Get("X-Forwarded-For")

	// If both empty, return IP from remote address
	if xRealIP == "" && xForwardedFor == "" {
		var remoteIP string

		// Remove port number if present
		if strings.ContainsRune(r.RemoteAddr, ':') {
			remoteIP, _, _ = net.SplitHostPort(r.RemoteAddr)
		} else {
			remoteIP = r.RemoteAddr
		}

		return remoteIP
	}

	// Check X-Forwarded-For for first non-private IP
	for _, address := range strings.Split(xForwardedFor, ",") {
		address = strings.TrimSpace(address)
		isPrivate, err := isPrivateAddress(address)
		if !isPrivate && err == nil {
			return address
		}
	}

	// Fallback to X-Real-IP
	return xRealIP
}
