package chusers

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/LucStr/chauth/internal/chconfig"
)

// Error is a ClickHouse exception returned over HTTP.
type Error struct {
	Code    int32
	Message string
}

func (e *Error) Error() string { return fmt.Sprintf("clickhouse code %d: %s", e.Code, e.Message) }

// Admin runs single statements on one instance's HTTP interface as the admin login.
type Admin struct {
	in     chconfig.Instance
	url    string
	client *http.Client
}

func NewAdmin(in chconfig.Instance) (*Admin, error) {
	u, err := url.Parse(in.HTTP)
	if err != nil {
		return nil, err
	}
	tlsConfig, err := in.TLSConfig(u.Hostname())
	if err != nil {
		return nil, err
	}
	return &Admin{in: in, url: in.HTTP, client: &http.Client{
		Timeout:   30 * time.Second,
		Transport: &http.Transport{TLSClientConfig: tlsConfig, MaxIdleConnsPerHost: 8, IdleConnTimeout: time.Minute},
	}}, nil
}

// Exec runs one statement as the admin.
func (a *Admin) Exec(ctx context.Context, stmt string) error {
	creds, err := a.in.Credentials()
	if err != nil {
		return err
	}
	return a.run(ctx, creds.Username, creds.Password, stmt, nil)
}

// Rows runs one query as the admin with FORMAT JSONEachRow and calls row for each line.
func (a *Admin) Rows(ctx context.Context, query string, row func([]byte) error) error {
	creds, err := a.in.Credentials()
	if err != nil {
		return err
	}
	return a.run(ctx, creds.Username, creds.Password, query+" FORMAT JSONEachRow", row)
}

// Ping checks that the admin login works.
func (a *Admin) Ping(ctx context.Context) error { return a.Exec(ctx, "SELECT 1") }

// Login checks that user can log in with password.
func (a *Admin) Login(ctx context.Context, user, password string) error {
	return a.run(ctx, user, password, "SELECT 1", nil)
}

// CancelQuery stops user's running query queryID by replacing it with an empty one under the same
// id; this needs no privilege, unlike KILL QUERY, which reads system.processes.
func (a *Admin) CancelQuery(ctx context.Context, user, password, queryID string) error {
	u, err := url.Parse(a.url)
	if err != nil {
		return err
	}
	u.RawQuery = url.Values{"replace_running_query": {"1"}, "query_id": {queryID}}.Encode()
	return a.runURL(ctx, u.String(), user, password, "SELECT 1", nil)
}

func (a *Admin) run(ctx context.Context, user, password, stmt string, row func([]byte) error) error {
	return a.runURL(ctx, a.url, user, password, stmt, row)
}

func (a *Admin) runURL(ctx context.Context, u, user, password, stmt string, row func([]byte) error) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u, strings.NewReader(stmt))
	if err != nil {
		return err
	}
	req.SetBasicAuth(user, password)
	resp, err := a.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<10))
		code, _ := strconv.ParseInt(resp.Header.Get("X-ClickHouse-Exception-Code"), 10, 32)
		return &Error{Code: int32(code), Message: strings.TrimSpace(string(body))}
	}
	if row == nil {
		_, err = io.Copy(io.Discard, resp.Body)
		return err
	}
	sc := bufio.NewScanner(resp.Body)
	sc.Buffer(make([]byte, 64<<10), 1<<20)
	for sc.Scan() {
		if err := row(sc.Bytes()); err != nil {
			return err
		}
	}
	return sc.Err()
}

func isCode(err error, code int32) bool {
	var e *Error
	return errors.As(err, &e) && e.Code == code
}
