package chconnect

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"slices"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/LucStr/chauth/internal/chapi"
)

func (e *Env) api(path string) string { return e.HTTPServer.String() + path }

// Discovery fetches serve's public discovery.
func (e *Env) Discovery(ctx context.Context) (*chapi.Discovery, error) {
	var d chapi.Discovery
	return &d, getJSON(ctx, e.HTTP, e.api(chapi.DiscoveryPath), "", &d)
}

// Access lists what this environment's token reaches.
func (e *Env) Access(ctx context.Context) ([]chapi.Access, error) {
	tok, err := e.Tokens.Token(ctx)
	if err != nil {
		return nil, err
	}
	var out []chapi.Access
	return out, getJSON(ctx, e.HTTP, e.api(chapi.AccessPath), tok, &out)
}

// Address is the shortest name that reaches instance/db: "<env>/<db>" when no other instance has a
// database of that name, else "<env>/<instance>/<db>"; without discovery always the long form.
func (e *Env) Address(d *chapi.Discovery, instance, db string) string {
	if d != nil {
		n := 0
		for _, in := range d.Instances {
			if slices.Contains(in.Databases, db) {
				n++
			}
		}
		if n == 1 {
			return e.Name + "/" + db
		}
	}
	return e.Name + "/" + instance + "/" + db
}

// PrintAccess writes what each named environment's token reaches to out, databases first, then named
// roles, and per-environment failures to errOut; an environment with nothing reachable gets the
// server's access help.
func (c *Connector) PrintAccess(ctx context.Context, out, errOut io.Writer, names []string) error {
	w := tabwriter.NewWriter(out, 0, 4, 2, ' ', 0)
	fmt.Fprintln(w, "DATABASE\tLEVEL")
	var roles, empty []string
	failed := false
	for _, name := range names {
		e := c.envs[name]
		access, err := e.Access(ctx)
		if err != nil {
			fmt.Fprintf(errOut, "%s: %v\n", name, err)
			failed = true
			continue
		}
		d, err := e.Discovery(ctx)
		if err != nil {
			d = nil
		}
		for _, a := range access {
			for _, db := range a.Databases {
				fmt.Fprintf(w, "%s\t%s\n", e.Address(d, a.Instance, db.Database), db.Level)
			}
			for _, r := range a.Roles {
				roles = append(roles, e.Name+"/"+a.Instance+"\t"+r)
			}
		}
		if len(access) == 0 {
			msg := name + ": nothing is reachable with this token."
			if d != nil && d.AccessHelp != "" {
				msg += " " + strings.Join(strings.Fields(d.AccessHelp), " ")
			}
			empty = append(empty, msg)
		}
	}
	if len(roles) > 0 {
		fmt.Fprintln(w, "INSTANCE\tROLE")
		for _, r := range roles {
			fmt.Fprintln(w, r)
		}
	}
	_ = w.Flush()
	for _, msg := range empty {
		fmt.Fprintln(out, msg)
	}
	if failed {
		return errors.New("some environments could not be listed")
	}
	return nil
}

func getJSON(ctx context.Context, client *http.Client, url, bearer string, v any) error {
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		var e chapi.Error
		_ = json.NewDecoder(resp.Body).Decode(&e)
		if e.Error == "" {
			e.Error = resp.Status
		}
		return fmt.Errorf("%s: %s", url, e.Error)
	}
	return json.NewDecoder(resp.Body).Decode(v)
}
