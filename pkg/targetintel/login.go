package targetintel

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
)

// The OAuth client used for the browser flow. These are the public installed
// application credentials the Google Cloud SDK ships with, so the consent
// screen and stored file behave exactly like `gcloud auth login`. Override
// with VC_TI_OAUTH_CLIENT_ID / VC_TI_OAUTH_CLIENT_SECRET to use another client.
const (
	defaultOAuthClientID     = "32555940559.apps.googleusercontent.com"
	defaultOAuthClientSecret = "ZmssLNjJy2998hD4CTg2ejr2"

	EnvOAuthClientID     = "VC_TI_OAUTH_CLIENT_ID"
	EnvOAuthClientSecret = "VC_TI_OAUTH_CLIENT_SECRET"
)

// LoginOptions controls the browser flow.
type LoginOptions struct {
	// OpenBrowser launches the consent URL. When nil or when it fails, the
	// URL is handed to Notify and the flow waits for the redirect anyway.
	OpenBrowser func(url string) error
	// Notify receives human-readable progress lines (the URL to visit).
	Notify func(format string, args ...any)
	// Timeout bounds the wait for the browser redirect.
	Timeout time.Duration
}

// LoginResult is what a completed browser login produced.
type LoginResult struct {
	Account string
	Path    string
}

func oauthConfig(redirectURL string) *oauth2.Config {
	id, secret := os.Getenv(EnvOAuthClientID), os.Getenv(EnvOAuthClientSecret)
	if id == "" {
		id, secret = defaultOAuthClientID, defaultOAuthClientSecret
	}

	return &oauth2.Config{
		ClientID:     id,
		ClientSecret: secret,
		Endpoint:     google.Endpoint,
		RedirectURL:  redirectURL,
		Scopes:       Scopes,
	}
}

// Login runs the loopback authorization-code flow with PKCE: start a
// listener on 127.0.0.1, send the user to Google's consent page, receive the
// code on the redirect, exchange it for a refresh token and store it.
func Login(ctx context.Context, opts LoginOptions) (*LoginResult, error) {
	if opts.Notify == nil {
		opts.Notify = func(string, ...any) {}
	}
	if opts.Timeout == 0 {
		opts.Timeout = 5 * time.Minute
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, fmt.Errorf("start loopback listener: %w", err)
	}
	defer func() { _ = ln.Close() }()

	conf := oauthConfig(fmt.Sprintf("http://%s/", ln.Addr().String()))
	state, err := randomString(16)
	if err != nil {
		return nil, err
	}
	verifier := oauth2.GenerateVerifier()

	authURL := conf.AuthCodeURL(state,
		oauth2.AccessTypeOffline,
		oauth2.ApprovalForce,
		oauth2.S256ChallengeOption(verifier),
	)

	type result struct {
		code string
		err  error
	}
	results := make(chan result, 1)
	srv := &http.Server{ReadHeaderTimeout: 10 * time.Second}
	srv.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		switch {
		case q.Get("state") != state:
			http.Error(w, "state mismatch", http.StatusBadRequest)
			results <- result{err: errors.New("oauth state mismatch")}
		case q.Get("error") != "":
			_, _ = fmt.Fprintf(w, "Authentication failed: %s. You can close this window.", q.Get("error"))
			results <- result{err: fmt.Errorf("authorization denied: %s", q.Get("error"))}
		case q.Get("code") == "":
			http.Error(w, "missing code", http.StatusBadRequest)
			results <- result{err: errors.New("redirect carried no authorization code")}
		default:
			_, _ = fmt.Fprint(w, "You are now authenticated with the VulnCheck CLI. You can close this window.")
			results <- result{code: q.Get("code")}
		}
	})
	go func() { _ = srv.Serve(ln) }()
	defer func() {
		shutdownCtx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_ = srv.Shutdown(shutdownCtx)
	}()

	opened := false
	if opts.OpenBrowser != nil {
		opened = opts.OpenBrowser(authURL) == nil
	}
	if opened {
		opts.Notify("Your browser has been opened to visit:\n\n    %s\n", authURL)
	} else {
		opts.Notify("Open this URL in a browser to continue:\n\n    %s\n", authURL)
	}

	var code string
	select {
	case res := <-results:
		if res.err != nil {
			return nil, res.err
		}
		code = res.code
	case <-time.After(opts.Timeout):
		return nil, errors.New("timed out waiting for the browser to complete authentication")
	case <-ctx.Done():
		return nil, ctx.Err()
	}

	tok, err := conf.Exchange(ctx, code, oauth2.VerifierOption(verifier))
	if err != nil {
		return nil, fmt.Errorf("exchange authorization code: %w", err)
	}

	account, err := Principal(ctx, conf.TokenSource(ctx, tok))
	if err != nil {
		return nil, fmt.Errorf("look up account: %w", err)
	}

	path, err := SaveCredentials(conf, tok, account)
	if err != nil {
		return nil, err
	}

	return &LoginResult{Account: account, Path: path}, nil
}

func randomString(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}

	return strings.TrimRight(base64.URLEncoding.EncodeToString(b), "="), nil
}
