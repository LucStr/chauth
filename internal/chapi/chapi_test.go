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

func TestFilterQuery(t *testing.T) {
	drop := func(k string) bool { return OneOf(k, "user", "password", CORSParam) }
	tests := []struct {
		raw, kept string
		values    []string
		err       bool
	}{
		{"query=SELECT+1&database=core", "query=SELECT+1", []string{"core"}, false},
		{"b=2&a=1;x=y&c=%3B&a=1", "b=2&a=1;x=y&c=%3B&a=1", nil, false},
		{"USER=x&Password=y&%75ser=z&keep=%20", "keep=%20", nil, false},
		{"Add_HTTP_Cors_Header=1&default_format=JSON", "default_format=JSON", nil, false},
		{"DataBase=a%2Fb&x&&y=", "x&y=", []string{"a/b"}, false},
		{"database=a&DATABASE=b", "", []string{"a", "b"}, false},
		{"%zz=1", "", nil, true},
	}
	for _, tt := range tests {
		kept, values, err := FilterQuery(tt.raw, "database", drop)
		if (err != nil) != tt.err || kept != tt.kept || strings.Join(values, ",") != strings.Join(tt.values, ",") {
			t.Errorf("%q: got %q %q %v, want %q %q", tt.raw, kept, values, err, tt.kept, tt.values)
		}
	}
	h := http.Header{"Access-Control-Allow-Origin": {"*"}, "access-control-expose-headers": {"x"}, "X-Clickhouse-Summary": {"{}"}}
	StripCORS(h)
	if len(h) != 1 || h.Get("X-ClickHouse-Summary") == "" {
		t.Errorf("after StripCORS: %v", h)
	}
}
