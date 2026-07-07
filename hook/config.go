package main

import (
	"fmt"
	"net"
	"os"
	"strings"
	"time"

	jsonpatch "github.com/evanphx/json-patch/v5"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
)

type config struct {
	allowedClientSpiffeIDs []spiffeid.ID
	listenAddr             net.Addr
	healthAddr             net.Addr
	path                   string
	claimsPatch            jsonpatch.Patch
	shutdownTimeout        time.Duration
}

func loadConfig() (config, error) {
	// Allowed client spiffe IDs
	var ids []spiffeid.ID
	for s := range strings.SplitSeq(os.Getenv("ALLOWED_CLIENT_SPIFFE_IDS"), ",") {
		s = strings.TrimSpace(s)
		if s == "" {
			continue
		}
		id, err := spiffeid.FromString(s)
		if err != nil {
			return config{}, fmt.Errorf("invalid ALLOWED_CLIENT_SPIFFE_IDS entry %q: %w", s, err)
		}
		ids = append(ids, id)
	}
	if len(ids) == 0 {
		return config{}, fmt.Errorf("ALLOWED_CLIENT_SPIFFE_IDS is required")
	}

	// Listening address
	addrStr := os.Getenv("LISTEN_ADDR")
	if addrStr == "" {
		addrStr = ":8443"
	}
	addr, err := net.ResolveTCPAddr("tcp", addrStr)
	if err != nil {
		return config{}, fmt.Errorf("invalid LISTEN_ADDR %q: %w", addrStr, err)
	}

	// Health check address
	healthAddrStr := os.Getenv("HEALTH_ADDR")
	if healthAddrStr == "" {
		healthAddrStr = ":8080"
	}
	healthAddr, err := net.ResolveTCPAddr("tcp", healthAddrStr)
	if err != nil {
		return config{}, fmt.Errorf("invalid HEALTH_ADDR %q: %w", healthAddrStr, err)
	}

	// Path to serve
	path := os.Getenv("HOOK_PATH")
	if path == "" {
		path = "/"
	}

	// Claims patch
	claimsPatchStr := os.Getenv("HOOK_CLAIMS_PATCH")
	if claimsPatchStr == "" {
		claimsPatchStr = `[{"op":"add","path":"/custom-hook","value":"tada"}]`
	}
	claimsPatch, err := jsonpatch.DecodePatch([]byte(claimsPatchStr))
	if err != nil {
		return config{}, fmt.Errorf("invalid HOOK_CLAIMS_PATCH: %w", err)
	}

	// Shutdown timeout
	shutdownTimeoutStr := os.Getenv("SHUTDOWN_TIMEOUT")
	if shutdownTimeoutStr == "" {
		shutdownTimeoutStr = "10s"
	}
	shutdownTimeout, err := time.ParseDuration(shutdownTimeoutStr)
	if err != nil {
		return config{}, fmt.Errorf("invalid SHUTDOWN_TIMEOUT %q: %w", shutdownTimeoutStr, err)
	}

	return config{
		allowedClientSpiffeIDs: ids,
		listenAddr:             addr,
		healthAddr:             healthAddr,
		path:                   path,
		claimsPatch:            claimsPatch,
		shutdownTimeout:        shutdownTimeout,
	}, nil
}
