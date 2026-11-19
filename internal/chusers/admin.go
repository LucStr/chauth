package chusers

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/LucStr/chauth/internal/chconfig"
	"github.com/LucStr/chauth/internal/rbac"
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

// Upstream reads the own grants of roles from system.grants and the databases with row policies.
func (a *Admin) Upstream(ctx context.Context, roles []string) (*rbac.Upstream, error) {
	quoted := make([]string, len(roles))
	for i, r := range roles {
		quoted[i] = Literal(r)
	}
	u := &rbac.Upstream{Grants: []rbac.RoleGrant{}, RowPolicyDatabases: []string{}}
	err := a.Rows(ctx, "SELECT role_name, access_type, ifNull(database, '') AS database, ifNull(table, '') AS table, "+
		"column IS NOT NULL AS column, is_partial_revoke FROM system.grants WHERE role_name IN ("+strings.Join(quoted, ", ")+")",
		func(line []byte) error {
			var row struct {
				Role     string `json:"role_name"`
				Access   string `json:"access_type"`
				Database string `json:"database"`
				Table    string `json:"table"`
				Column   int    `json:"column"`
				Revoke   int    `json:"is_partial_revoke"`
			}
			if err := json.Unmarshal(line, &row); err != nil {
				return err
			}
			u.Grants = append(u.Grants, rbac.RoleGrant{Role: row.Role, Access: row.Access, Database: row.Database, Table: row.Table,
				Column: row.Column != 0, PartialRevoke: row.Revoke != 0})
			return nil
		})
	if err != nil {
		return nil, err
	}
	err = a.Rows(ctx, "SELECT DISTINCT database FROM system.row_policies", func(line []byte) error {
		var row struct {
			Database string `json:"database"`
		}
		if err := json.Unmarshal(line, &row); err != nil {
			return err
		}
		u.RowPolicyDatabases = append(u.RowPolicyDatabases, row.Database)
		return nil
	})
	return u, err
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
