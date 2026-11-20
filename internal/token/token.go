// Package token verifies database tokens against an OIDC issuer and reads the claims chauth acts on.
package token

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/go-jose/go-jose/v4"

	"github.com/LucStr/chauth/internal/config"
)

type Claims struct {
	Subject  string
	ClientID string
	Username string
	// Groups carry the configured prefix.
	Groups []string
	Scopes []string
	Expiry time.Time
	// Details are the authorization_details rows for chauth; nil when the token has no such claim.
	Details []Detail
}

type Verifier struct {
	cfg      config.OIDC
	verifier atomic.Pointer[oidc.IDTokenVerifier]
	keys     atomic.Pointer[keySet]
}

func NewVerifier(cfg config.OIDC) *Verifier { return &Verifier{cfg: cfg} }

// Start runs OIDC discovery and a first JWKS fetch, retrying until both succeed or ctx ends.
func (v *Verifier) Start(ctx context.Context, log *slog.Logger) {
	for wait := time.Second; ; wait = min(2*wait, 30*time.Second) {
		err := v.discover(ctx)
		if err == nil {
			return
		}
		log.Warn("oidc issuer not ready", "issuer", v.cfg.Issuer, "error", err)
		select {
		case <-ctx.Done():
			return
		case <-time.After(wait):
		}
	}
}

func (v *Verifier) discover(ctx context.Context) error {
	provider, err := oidc.NewProvider(ctx, v.cfg.Issuer)
	if err != nil {
		return err
	}
	var meta struct {
		Issuer  string   `json:"issuer"`
		JWKSURL string   `json:"jwks_uri"`
		Algs    []string `json:"id_token_signing_alg_values_supported"`
	}
	if err := provider.Claims(&meta); err != nil {
		return err
	}
	var algs []string
	for _, a := range meta.Algs {
		if slices.Contains(asymmetricAlgs, jose.SignatureAlgorithm(a)) {
			algs = append(algs, a)
		}
	}
	if len(algs) == 0 {
		algs = []string{oidc.RS256}
	}
	keys := &keySet{url: meta.JWKSURL, every: refetchEvery}
	if err := keys.fetch(ctx); err != nil {
		return err
	}
	v.keys.Store(keys)
	v.verifier.Store(oidc.NewVerifier(meta.Issuer, keys, &oidc.Config{ClientID: v.cfg.Audience, SupportedSigningAlgs: algs}))
	return nil
}

var asymmetricAlgs = []jose.SignatureAlgorithm{jose.RS256, jose.RS384, jose.RS512, jose.ES256, jose.ES384, jose.ES512,
	jose.PS256, jose.PS384, jose.PS512, jose.EdDSA}

// refetchEvery bounds how often a token signed by an unknown key makes chauth fetch the key set.
const refetchEvery = 10 * time.Second

// retryAfter is how soon a failed key-set fetch may be tried again.
const retryAfter = time.Second

// keySet is the issuer's JWKS. A token whose key is not in it triggers at most one fetch per
// every after a successful fetch, or retryAfter after a failed one; tokens in between fail
// without one, so unauthenticated clients cannot drive fetches.
type keySet struct {
	url   string
	every time.Duration

	mu        sync.Mutex
	keys      []jose.JSONWebKey
	fetchedAt time.Time
	failedAt  time.Time
	inflight  bool
}

// due reports whether a fetch may start now; k.mu must be held.
func (k *keySet) due() bool {
	return !k.inflight && time.Since(k.fetchedAt) >= k.every && time.Since(k.failedAt) >= retryAfter
}

func (k *keySet) VerifySignature(ctx context.Context, raw string) ([]byte, error) {
	jws, err := jose.ParseSignedCompact(raw, asymmetricAlgs)
	if err != nil || len(jws.Signatures) != 1 {
		return nil, errors.New("malformed token")
	}
	kid := jws.Signatures[0].Header.KeyID
	if payload, ok := k.verify(jws, kid); ok {
		return payload, nil
	}
	if err := k.fetch(ctx); err != nil {
		return nil, fmt.Errorf("fetch keys: %w", err)
	}
	if payload, ok := k.verify(jws, kid); ok {
		return payload, nil
	}
	return nil, errors.New("failed to verify signature")
}

func (k *keySet) verify(jws *jose.JSONWebSignature, kid string) ([]byte, bool) {
	k.mu.Lock()
	keys := k.keys
	k.mu.Unlock()
	for _, key := range keys {
		if kid == "" || key.KeyID == kid {
			if payload, err := jws.Verify(&key); err == nil {
				return payload, true
			}
		}
	}
	return nil, false
}

// fetch replaces the keys when a fetch is due and returns nil when it is not.
func (k *keySet) fetch(ctx context.Context) error {
	k.mu.Lock()
	if !k.due() {
		k.mu.Unlock()
		return nil
	}
	k.inflight = true
	k.mu.Unlock()
	keys, err := k.get(ctx)
	k.mu.Lock()
	defer k.mu.Unlock()
	k.inflight = false
	if err != nil {
		k.failedAt = time.Now()
		return err
	}
	k.keys, k.fetchedAt, k.failedAt = keys, time.Now(), time.Time{}
	return nil
}

func (k *keySet) get(ctx context.Context) ([]jose.JSONWebKey, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, k.url, nil)
	if err != nil {
		return nil, err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("GET %s: %s", k.url, resp.Status)
	}
	var set struct {
		Keys []json.RawMessage `json:"keys"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&set); err != nil {
		return nil, fmt.Errorf("GET %s: %w", k.url, err)
	}
	var keys []jose.JSONWebKey
	for _, raw := range set.Keys {
		var key jose.JSONWebKey
		if json.Unmarshal(raw, &key) == nil && key.Use != "enc" && key.IsPublic() {
			keys = append(keys, key)
		}
	}
	return keys, nil
}

// Ready reports whether discovery and the first JWKS fetch succeeded.
func (v *Verifier) Ready() bool { return v.verifier.Load() != nil }

// ErrDenied wraps every reason a token is refused; its message is safe to show the client.
var ErrDenied = errors.New("token rejected")

func (v *Verifier) Verify(ctx context.Context, raw string) (Claims, error) {
	verifier := v.verifier.Load()
	if verifier == nil {
		return Claims{}, fmt.Errorf("%w: issuer not reachable yet", ErrDenied)
	}
	tok, err := verifier.Verify(ctx, raw)
	if err != nil {
		return Claims{}, fmt.Errorf("%w: %s", ErrDenied, reason(err))
	}
	var all map[string]any
	if err := tok.Claims(&all); err != nil {
		return Claims{}, fmt.Errorf("%w: unreadable claims", ErrDenied)
	}
	c := Claims{Subject: tok.Subject, Expiry: tok.Expiry}
	if c.Subject == "" {
		return Claims{}, fmt.Errorf("%w: no sub claim", ErrDenied)
	}
	c.ClientID, _ = all[v.cfg.ClientIDClaim].(string)
	if c.ClientID == "" {
		c.ClientID, _ = all["azp"].(string)
	}
	if len(v.cfg.AllowedClients) > 0 && !slices.Contains(v.cfg.AllowedClients, c.ClientID) {
		return Claims{}, fmt.Errorf("%w: client %q is not allowed", ErrDenied, c.ClientID)
	}
	c.Username, _ = all[v.cfg.UsernameClaim].(string)
	if c.Username == "" {
		return Claims{}, fmt.Errorf("%w: no %s claim", ErrDenied, v.cfg.UsernameClaim)
	}
	groups, err := stringList(all[v.cfg.GroupsClaim], false)
	if err != nil {
		return Claims{}, fmt.Errorf("%w: claim %s: %v", ErrDenied, v.cfg.GroupsClaim, err)
	}
	for _, g := range groups {
		c.Groups = append(c.Groups, v.cfg.GroupsPrefix+g)
	}
	scope := all["scope"]
	if scope == nil {
		scope = all["scp"]
	}
	if c.Scopes, err = stringList(scope, true); err != nil {
		return Claims{}, fmt.Errorf("%w: claim scope: %v", ErrDenied, err)
	}
	if c.Details, err = details(tok, v.cfg.Audience); err != nil {
		return Claims{}, fmt.Errorf("%w: claim %s: %v", ErrDenied, DetailsClaim, err)
	}
	if c.Details == nil && slices.Contains(v.cfg.RequireDetailsClients, c.ClientID) {
		return Claims{}, fmt.Errorf("%w: client %q must send the %s claim", ErrDenied, c.ClientID, DetailsClaim)
	}
	return c, nil
}

// details reads the claim from the raw payload, so its key must be spelled exactly and appear once.
func details(tok *oidc.IDToken, audience string) ([]Detail, error) {
	var payload json.RawMessage
	if err := tok.Claims(&payload); err != nil {
		return nil, err
	}
	fields, err := ObjectFields(payload)
	if err != nil {
		return nil, err
	}
	var raw json.RawMessage
	for _, f := range fields {
		if f.Key == DetailsClaim {
			if raw != nil {
				return nil, errors.New("appears twice")
			}
			raw = f.Value
		}
	}
	if raw == nil {
		return nil, nil
	}
	return ParseDetails(raw, DetailsType, audience)
}

func reason(err error) string {
	var expired *oidc.TokenExpiredError
	switch {
	case errors.As(err, &expired):
		return "token expired"
	case strings.Contains(err.Error(), "audience"):
		return "wrong audience"
	case strings.Contains(err.Error(), "different provider"):
		return "wrong issuer"
	case strings.Contains(err.Error(), "signature"):
		return "bad signature"
	default:
		return "invalid token"
	}
}

// stringList reads a claim that is an array of strings or a single string; split breaks the string
// on spaces (the OAuth scope format), otherwise it is one entry.
func stringList(v any, split bool) ([]string, error) {
	switch v := v.(type) {
	case nil:
		return nil, nil
	case string:
		if split {
			return strings.Fields(v), nil
		}
		if v == "" {
			return nil, nil
		}
		return []string{v}, nil
	case []any:
		out := make([]string, 0, len(v))
		for _, e := range v {
			s, ok := e.(string)
			if !ok {
				return nil, errors.New("entries must be strings")
			}
			out = append(out, s)
		}
		return out, nil
	default:
		return nil, errors.New("must be a string or an array of strings")
	}
}
