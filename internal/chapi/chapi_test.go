package chapi

import (
	"io"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
)

// TestNoReplay sends two requests over one kept-alive upstream connection; the upstream reads the
// second and closes without answering. Without NoReplay the transport sends the GET a third time.
func TestNoReplay(t *testing.T) {
	var seen atomic.Int32
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.ReadAll(r.Body)
		if seen.Add(1)%2 == 0 {
			conn, _, _ := http.NewResponseController(w).Hijack()
			conn.Close()
			return
		}
		_, _ = io.WriteString(w, "ok")
	}))
	defer up.Close()
	target, _ := url.Parse(up.URL)
	for _, tt := range []struct {
		name     string
		noReplay bool
		want     int32
	}{{"with NoReplay", true, 2}, {"without", false, 3}} {
		for _, method := range []string{http.MethodGet, http.MethodPost} {
			if method == http.MethodPost && !tt.noReplay {
				continue
			}
			seen.Store(0)
			proxy := httptest.NewServer(&httputil.ReverseProxy{
				Transport: &http.Transport{},
				Rewrite: func(pr *httputil.ProxyRequest) {
					pr.SetURL(target)
					if tt.noReplay {
						NoReplay(pr.Out)
					}
				},
				ErrorHandler: func(w http.ResponseWriter, _ *http.Request, _ error) { w.WriteHeader(http.StatusBadGateway) },
			})
			var statuses []int
			for range 2 {
				req, _ := http.NewRequest(method, proxy.URL, nil)
				if method == http.MethodPost {
					req.Body = io.NopCloser(strings.NewReader(""))
				}
				resp, err := http.DefaultClient.Do(req)
				if err != nil {
					t.Fatal(err)
				}
				resp.Body.Close()
				statuses = append(statuses, resp.StatusCode)
			}
			proxy.Close()
			if got := seen.Load(); got != tt.want || tt.noReplay && statuses[1] != http.StatusBadGateway {
				t.Errorf("%s %s: upstream saw %d requests (want %d), statuses %v", tt.name, method, got, tt.want, statuses)
			}
		}
	}
}
