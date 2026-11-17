// Package connect holds the connector's building blocks: the connect.yaml format, database tokens
// from a browser login or a token file, and the per-user service that runs the connector.
package connect

import (
	"context"
	"errors"
	"log/slog"
	"sync"
	"time"

	"github.com/zalando/go-keyring"
)

// TokenSource hands out a database token for one connection or request.
type TokenSource interface {
	Token(ctx context.Context) (string, error)
}

type Options struct {
	Issuer   string
	ClientID string
	// Resource is sent as the RFC 8707 resource parameter and becomes the token's audience.
	Resource string
	Scope    string
	// CallbackPort is the loopback port of the login redirect; 0 picks a free one (RFC 8252).
	CallbackPort int
	// OpenBrowser opens the login URL; the URL is also logged in case it fails.
	OpenBrowser func(url string) error
	Store       TokenStore
	// StoreKey names the refresh token in Store.
	StoreKey string
}

// TokenStore keeps the refresh token between runs.
type TokenStore interface {
	Get(key string) (string, error)
	Set(key, value string) error
	Delete(key string) error
}

// KeychainService is the OS keychain service the refresh tokens are kept under.
const KeychainService = "chauth"

// Keychain stores tokens in the OS keychain (macOS Keychain, Secret Service on Linux).
type Keychain struct{}

func (Keychain) Get(key string) (string, error) { return keyring.Get(KeychainService, key) }
func (Keychain) Set(key, value string) error    { return keyring.Set(KeychainService, key, value) }
func (Keychain) Delete(key string) error {
	if err := keyring.Delete(KeychainService, key); err != nil && !errors.Is(err, keyring.ErrNotFound) {
		return err
	}
	return nil
}

// Connector gets database tokens through a browser login and keeps them fresh with the refresh token.
type Connector struct {
	opts Options
	log  *slog.Logger

	mu        sync.Mutex
	disc      *discovery
	access    string
	accessExp time.Time
	refreshed string
}

// accessMargin is how long a cached access token must still be valid; serve checks it only at connect.
const accessMargin = 30 * time.Second

func New(opts Options, log *slog.Logger) *Connector {
	return &Connector{opts: opts, log: log}
}

// Login runs the browser login now, ignoring any stored refresh token, and keeps its tokens.
func (c *Connector) Login(ctx context.Context) error {
	c.mu.Lock()
	c.access, c.refreshed = "", ""
	c.mu.Unlock()
	if err := c.opts.Store.Delete(c.opts.StoreKey); err != nil {
		c.log.Warn("could not clear the stored refresh token", "error", err)
	}
	_, err := c.Token(ctx)
	return err
}

// Token returns a database token valid for at least accessMargin, refreshing or logging in as needed.
func (c *Connector) Token(ctx context.Context) (string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.access != "" && time.Until(c.accessExp) > accessMargin {
		return c.access, nil
	}
	if c.disc == nil {
		d, err := discover(ctx, c.opts.Issuer)
		if err != nil {
			return "", err
		}
		c.disc = d
	}
	refreshToken := c.refreshed
	if refreshToken == "" {
		refreshToken, _ = c.opts.Store.Get(c.opts.StoreKey)
	}
	var tok *tokenResponse
	var err error
	if refreshToken != "" {
		tok, err = c.refresh(ctx, c.disc, refreshToken)
		if err != nil {
			c.log.Info("refresh failed, logging in again", "error", err)
		}
	}
	if tok == nil {
		if tok, err = c.login(ctx, c.disc); err != nil {
			return "", err
		}
	}
	c.access = tok.AccessToken
	c.accessExp = time.Now().Add(time.Duration(tok.ExpiresIn) * time.Second)
	if tok.RefreshToken != "" {
		c.refreshed = tok.RefreshToken
		if err := c.opts.Store.Set(c.opts.StoreKey, tok.RefreshToken); err != nil {
			c.log.Warn("could not save the refresh token; you will log in again next run", "error", err)
		}
	}
	return c.access, nil
}
