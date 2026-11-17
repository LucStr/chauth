package token

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"

	"github.com/LucStr/chauth/internal/config"
)

// TestUnknownKeyRefetch: tokens signed by keys the issuer does not publish fetch the key set at
// most once per refetchEvery; a key the issuer adds is picked up at the next allowed fetch, and a
// failed fetch is retried after retryAfter, not after a whole window.
func TestUnknownKeyRefetch(t *testing.T) {
	known, _ := rsa.GenerateKey(rand.Reader, 2048)
	added, _ := rsa.GenerateKey(rand.Reader, 2048)
	third, _ := rsa.GenerateKey(rand.Reader, 2048)
	var failNext atomic.Bool
	var mu sync.Mutex
	published := []jose.JSONWebKey{{Key: &known.PublicKey, KeyID: "k1", Algorithm: "RS256", Use: "sig"}}
	var fetches atomic.Int32
	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/.well-known/openid-configuration":
			_ = json.NewEncoder(w).Encode(map[string]any{"issuer": srv.URL, "jwks_uri": srv.URL + "/jwks",
				"id_token_signing_alg_values_supported": []string{"RS256", "HS256"}})
		case "/jwks":
			fetches.Add(1)
			if failNext.Swap(false) {
				http.Error(w, "unavailable", http.StatusServiceUnavailable)
				return
			}
			mu.Lock()
			defer mu.Unlock()
			_ = json.NewEncoder(w).Encode(jose.JSONWebKeySet{Keys: published})
		}
	}))
	defer srv.Close()
	sign := func(key *rsa.PrivateKey, kid string) string {
		signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: jose.JSONWebKey{Key: key, KeyID: kid}}, nil)
		if err != nil {
			t.Fatal(err)
		}
		raw, err := jwt.Signed(signer).Claims(map[string]any{"iss": srv.URL, "aud": "aud", "sub": "s", "email": "a@example.com",
			"client_id": "cli", "exp": time.Now().Add(time.Hour).Unix(), "scope": "clickhouse:read"}).Serialize()
		if err != nil {
			t.Fatal(err)
		}
		return raw
	}
	v := NewVerifier(config.OIDC{Issuer: srv.URL, Audience: "aud", UsernameClaim: "email", ClientIDClaim: "client_id", AllowedClients: []string{"cli"}})
	v.Start(context.Background(), slog.New(slog.NewTextHandler(io.Discard, nil)))
	ctx := context.Background()
	stranger, _ := rsa.GenerateKey(rand.Reader, 2048)
	age := func() {
		k := v.keys.Load()
		k.mu.Lock()
		k.fetchedAt = k.fetchedAt.Add(-refetchEvery - time.Second)
		k.mu.Unlock()
	}
	steps := []struct {
		name   string
		before func()
		token  string
		ok     bool
		want   int32 // fetches after the step
	}{
		{"known key", nil, sign(known, "k1"), true, 1},
		{"unknown kid right after the first fetch", nil, sign(stranger, "nope"), false, 1},
		{"unknown kid once the window passed", age, sign(stranger, "nope"), false, 2},
		{"unknown kid again", nil, sign(stranger, "nope"), false, 2},
		{"bad signature under a known kid", nil, sign(stranger, "k1"), false, 2},
		{"rotated key before the window passed", func() {
			mu.Lock()
			published = append(published, jose.JSONWebKey{Key: &added.PublicKey, KeyID: "k2", Algorithm: "RS256", Use: "sig"})
			mu.Unlock()
		}, sign(added, "k2"), false, 2},
		{"rotated key after it", age, sign(added, "k2"), true, 3},
		{"rotation while the issuer fails", func() {
			mu.Lock()
			published = append(published, jose.JSONWebKey{Key: &third.PublicKey, KeyID: "k3", Algorithm: "RS256", Use: "sig"})
			mu.Unlock()
			failNext.Store(true)
			age()
		}, sign(third, "k3"), false, 4},
		{"within the retry backoff", nil, sign(third, "k3"), false, 4},
		{"after the retry backoff", func() {
			k := v.keys.Load()
			k.mu.Lock()
			k.failedAt = k.failedAt.Add(-retryAfter - 100*time.Millisecond)
			k.mu.Unlock()
		}, sign(third, "k3"), true, 5},
	}
	for _, s := range steps {
		if s.before != nil {
			s.before()
		}
		for range 20 {
			if _, err := v.Verify(ctx, s.token); (err == nil) != s.ok {
				t.Fatalf("%s: err %v, want ok %v", s.name, err, s.ok)
			}
		}
		if got := fetches.Load(); got != s.want {
			t.Fatalf("%s: %d key-set fetches, want %d", s.name, got, s.want)
		}
	}
}
