package main

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"slices"
	"time"

	jsonpatch "github.com/evanphx/json-patch/v5"
	"github.com/spiffe/go-spiffe/v2/bundle/x509bundle"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/spiffetls/tlsconfig"
	"github.com/spiffe/go-spiffe/v2/svid/x509svid"
)

type HookAction string

const (
	HookActionAllow HookAction = "allow"
	HookActionDeny  HookAction = "deny"
)

// subject is a validated subject token.
type subject struct {
	Claims map[string]any `json:"claims"`
}

// actor is a validated actor token and the delegation chain it extends.
type actor struct {
	Claims         map[string]any  `json:"claims"`
	PreviousActors []exchangeActor `json:"previous_actors,omitempty"`
}

// exchangeActor identifies a party in a delegation chain.
type exchangeActor struct {
	Subject string `json:"sub"`
	Issuer  string `json:"iss"`
}

// client is the authenticated OAuth client making a token exchange request.
type client struct {
	ID string `json:"id"`
}

// request holds the parameters of a token exchange request as
// supplied by the caller. Unlike token claims, these have not been
// verified by a token signature and should be treated as untrusted.
type request struct {
	SubjectTokenType   string   `json:"subject_token_type"`
	ActorTokenType     string   `json:"actor_token_type,omitempty"`
	RequestedTokenType string   `json:"requested_token_type,omitempty"`
	Audience           []string `json:"audience,omitempty"`
	Scope              []string `json:"scope"`
}

// hookRequest is the HTTP body sent to the hook by Credex.
type hookRequest struct {
	Subject        subject        `json:"subject"`
	Actor          actor          `json:"actor,omitempty"`
	Client         client         `json:"client"`
	Request        request        `json:"request"`
	OutboundClaims map[string]any `json:"outbound_claims"`
}

// hookResponse is the HTTP response Credex expects the hook to return.
type hookResponse struct {
	ClaimsPatch  jsonpatch.Patch `json:"claims_patch,omitempty"`
	Action       HookAction      `json:"action"`
	ActionReason string          `json:"action_reason,omitempty"`
}

type x509Source interface {
	x509svid.Source
	x509bundle.Source
}

type server struct {
	logger       *slog.Logger
	mux          *http.ServeMux
	httpServer   *http.Server
	healthServer *http.Server
}

func newServer(path string, claimsPatch jsonpatch.Patch, logger *slog.Logger) *server {
	mux := http.NewServeMux()
	mux.HandleFunc(path, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}

		// Older versions of Credex send the legacy payload format, with
		// subject_claims at the top level rather than under subject.
		var req struct {
			hookRequest
			LegacySubjectClaims map[string]any `json:"subject_claims"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, fmt.Sprintf("bad request: %s", err), http.StatusBadRequest)
			return
		}
		subjectClaims := req.Subject.Claims
		if subjectClaims == nil {
			subjectClaims = req.LegacySubjectClaims
		}

		resp := hookResponse{
			Action:      HookActionAllow,
			ClaimsPatch: claimsPatch,
		}

		// Deny request for 'fake-audience'
		if aud, ok := subjectClaims["aud"]; ok {
			if auds, ok := aud.([]any); ok && slices.Contains(auds, "fake-audience") {
				resp = hookResponse{
					Action:       HookActionDeny,
					ActionReason: "Exchange not permitted for target audience",
				}
			}
		}

		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(resp); err != nil {
			logger.With("error", err).ErrorContext(r.Context(), "failed to write response")
		}
	})

	return &server{
		logger: logger,
		mux:    mux,
	}
}

func (s *server) run(ctx context.Context, x509Source x509Source, allowedClientSpiffeIDs []spiffeid.ID, listenAddr, healthAddr net.Addr, shutdownTimeout time.Duration) error {
	healthMux := http.NewServeMux()
	healthMux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	s.healthServer = &http.Server{Handler: healthMux}
	healthLn, err := net.Listen(healthAddr.Network(), healthAddr.String())
	if err != nil {
		return fmt.Errorf("failed to listen on health addr %s: %w", healthAddr, err)
	}
	s.logger.With("address", healthAddr).InfoContext(ctx, "health server listening")
	healthServerErr := make(chan error, 1)
	go func() {
		if err := s.healthServer.Serve(healthLn); err != nil && err != http.ErrServerClosed {
			healthServerErr <- fmt.Errorf("health server error: %w", err)
		}
		close(healthServerErr)
	}()

	tlsCfg := tlsconfig.MTLSServerConfig(x509Source, x509Source, tlsconfig.AuthorizeOneOf(allowedClientSpiffeIDs...))
	ln, err := tls.Listen(listenAddr.Network(), listenAddr.String(), tlsCfg)
	if err != nil {
		return fmt.Errorf("failed to listen on %s: %w", listenAddr, err)
	}

	s.httpServer = &http.Server{Handler: s.mux}

	s.logger.With("address", listenAddr).InfoContext(ctx, "listening")
	serveErr := make(chan error, 1)
	go func() {
		if err := s.httpServer.Serve(ln); err != nil && err != http.ErrServerClosed {
			serveErr <- fmt.Errorf("server error: %w", err)
		}
		close(serveErr)
	}()

	select {
	case err := <-serveErr:
		return err
	case err := <-healthServerErr:
		return err
	case <-ctx.Done():
		s.logger.InfoContext(ctx, "shutting down")
		ctx, cncl := context.WithTimeout(context.WithoutCancel(ctx), shutdownTimeout)
		defer cncl()
		var errs []error
		if err := s.healthServer.Shutdown(ctx); err != nil {
			errs = append(errs, fmt.Errorf("health server shutdown error: %w", err))
		}
		if err := s.httpServer.Shutdown(ctx); err != nil {
			errs = append(errs, fmt.Errorf("shutdown error: %w", err))
		}
		errs = append(errs, <-serveErr, <-healthServerErr)
		return errors.Join(errs...)
	}
}
