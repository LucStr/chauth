# chauth

chauth lets people and programs log in to ClickHouse with a short-lived OIDC access token instead of
a database password. A client connects to chauth with the token; chauth verifies it, looks up what
the holder may do in Kubernetes-style role bindings, creates a temporary ClickHouse user with exactly
the upstream roles those bindings give, logs in upstream as that user and passes the traffic
through. When the user is no longer used, chauth drops it. Both ClickHouse protocols are served:
native over TLS and HTTPS.

```
clickhouse-client --host chauth.example.com --port 9440 --secure --jwt "$TOKEN" -d core
curl -H "Authorization: Bearer $TOKEN" "https://chauth.example.com:8443/?database=core" --data-binary 'SELECT 1'
```

## The picture

```
ClickHouse client ──▶ chauth connect ──TLS──▶ chauth serve ──TLS──▶ ClickHouse
 (localhost,           (laptop or agent:        (next to ClickHouse:    (as chauth_tmp_…,
  no password)          adds the token)          checks the token and    a temp user with
                                                 the bindings)           exactly the roles)
```

1. A client (`clickhouse-client`, DBeaver, a driver, `curl`) talks to **`chauth connect`** on
   `localhost`, naming the database as `<env>/<db>`. The connector picks the environment, gets a
   token for it (browser login, or a token file kept fresh by something else) and forwards the
   connection or request over TLS with the token as the password or bearer.
2. **`chauth serve`** verifies the token against the issuer (signature, issuer, audience, expiry,
   client allowlist), reads the user and groups, and evaluates the `ChRole` / `ChRoleBinding` rules,
   capped by the token's scope (`clickhouse:read` or `clickhouse:write`).
3. It creates or reuses a **temp user** `chauth_tmp_<sub8>_<nonce><rand6>` with `VALID UNTIL`, an
   optional `HOST IP`, `log_comment = '<user>' CONST` (and `readonly = 2 CONST` at read level) and
   the upstream roles the rules give, then logs in upstream as it. `system.query_log` shows one
   user per person, and ClickHouse, not chauth, enforces every grant.
4. Native connections are checked when they open and cut after `maxConnectionAge` (12 h); every HTTP
   request is checked on its own. A temp user is handed out for at most `leaseDuration`, dropped
   after its last use, and a sweep drops expired temp users of any process.

Clients can also skip the connector and send the token directly, as in the example above.

## What chauth is not

- **Not a fine-grained authorization engine.** chauth decides which upstream roles a person gets:
  per database at read or write, or named roles from an allowlist. Table, column and row rules are
  ordinary ClickHouse grants and row policies on those roles.
- **Not a query firewall.** chauth never reads query text; rights come only from the roles.
- **Not a connection pooler.** Every native client connection is one upstream connection.

## Quickstart: on a laptop

1. Get a `connect.yaml` for your deployment (from whoever runs chauth) into
   `~/.config/chauth/connect.yaml` (macOS: `~/Library/Application Support/chauth/connect.yaml`), or
   point `$CHAUTH_CONFIG` or `--config` at it. Example: [`examples/connect.yaml`](examples/connect.yaml).
2. `chauth login prod` opens the browser, stores the refresh token in the OS keychain and lists what
   you can reach. `chauth ls [env]` lists it again.
3. `chauth connect`, or `chauth service install` to run it at login (launchd on macOS, a systemd
   user unit on Linux; `chauth service uninstall` removes it).
4. Connect with any client, no password:

```
clickhouse-client --host 127.0.0.1 --port 9000 -d prod/core
curl 'http://127.0.0.1:8123/?database=prod/core' --data-binary 'SELECT 1'
```

There is no default environment on these ports: a bare `core` fails and lists the environments. A
listener bound to one environment (`listeners: [{listen: 127.0.0.1:9001, listenHTTP:
127.0.0.1:8124, env: test}]`) accepts bare names, for tools that browse by database name.
`chauth logout <env>` forgets the stored login. Any process of yours that reaches the local ports
connects with your rights, the same trade-off as other local database proxies.

## Quickstart: on a server

1. Prepare ClickHouse ([below](#upstream-setup)) and store the admin user's credentials as
   `{"username": "chauth_admin", "password": "…"}` in a file only chauth can read.
2. Write the serve config ([`examples/config.yaml`](examples/config.yaml), reference in
   [`docs/config.md`](docs/config.md)) and the rules ([`examples/rbac`](examples/rbac)).
3. Check the rules: `chauth lint --config config.yaml rbac/`. Run the same in CI with the image.
4. Run it:

```
docker run -v /etc/chauth:/etc/chauth -p 9440:9440 -p 8443:8443 -p 8080:8080 \
  ghcr.io/lucstr/chauth:vX.Y.Z serve --config /etc/chauth/config.yaml
```

The image runs as non-root and needs no writable filesystem. `GET :8080/healthz` answers while the
process runs, `GET :8080/readyz` once the issuer's keys and a valid rules set are loaded. On the
HTTPS port, `GET /.well-known/chauth` publishes the addresses, issuer, client and scopes for
connectors, and `GET /v1/access` with a bearer token lists what that token reaches. With the
standard `OTEL_EXPORTER_OTLP_*` variables set, spans, metrics and logs go out over OTLP with
`service.name=chauth`; every log line also goes to stdout as JSON.

Binaries for macOS and Linux (amd64, arm64) are attached to each
[release](https://github.com/LucStr/chauth/releases). A binary downloaded with a browser on macOS is
quarantined; download it with `curl` or run `xattr -d com.apple.quarantine chauth`.

## Upstream setup

Run once per ClickHouse service as an administrator: one read and one write role per served
database (names from `roleTemplate`, default `chauth_{database}_{level}`), a read role for each
read-only database, any named roles you want to grant, and the admin user. This is
[`examples/clickhouse-setup.sql`](examples/clickhouse-setup.sql), which the tests run as is; adapt
the databases, grants and password:

```sql
-- Upstream objects chauth needs, for the databases core and otel and the read-only database system.
-- The tests run this file as is, so the admin's grants here are the complete set chauth relies on.

-- One read and one write role per database in instances[].databases (roleTemplate chauth_{database}_{level}).
CREATE ROLE chauth_core_read;
GRANT SHOW, SELECT ON core.* TO chauth_core_read;
CREATE ROLE chauth_core_write;
GRANT SHOW, SELECT, INSERT, ALTER, CREATE TABLE, CREATE VIEW, DROP TABLE, DROP VIEW, TRUNCATE, OPTIMIZE ON core.* TO chauth_core_write;
CREATE ROLE chauth_otel_read;
GRANT SHOW, SELECT ON otel.* TO chauth_otel_read;
CREATE ROLE chauth_otel_write;
GRANT SHOW, SELECT, INSERT, ALTER, CREATE TABLE, CREATE VIEW, DROP TABLE, DROP VIEW, TRUNCATE, OPTIMIZE ON otel.* TO chauth_otel_write;

-- A database in instances[].readOnlyDatabases needs only its read role.
CREATE ROLE chauth_system_read;
GRANT SELECT ON system.parts TO chauth_system_read;
GRANT SELECT ON system.settings_changes TO chauth_system_read;

-- A role granted by name (instances[].roles).
CREATE ROLE chauth_querylog_read;
GRANT SELECT ON system.query_log TO chauth_querylog_read;
GRANT CLUSTER ON *.* TO chauth_querylog_read;
GRANT REMOTE ON *.* TO chauth_querylog_read;

-- The admin login of credentialsFile. In production add HOST IP '<network chauth connects from>'.
-- No ALTER USER: ALTER USER <prefix>x RENAME TO y passes the prefix check and leaves the prefix.
CREATE USER chauth_admin IDENTIFIED WITH sha256_password BY 'admin-secret';
GRANT CREATE USER, DROP USER ON chauth_tmp_* TO chauth_admin;
GRANT chauth_core_read, chauth_core_write, chauth_otel_read, chauth_otel_write, chauth_system_read, chauth_querylog_read TO chauth_admin WITH ADMIN OPTION;
GRANT SELECT(name, valid_until) ON system.users TO chauth_admin;
```

- `CREATE USER, DROP USER ON chauth_tmp_*` lets the admin create and drop only users with the
  temp-user prefix (`tempUserPrefix`).
- Every role a temp user may get must be granted to the admin `WITH ADMIN OPTION`; a role chauth
  cannot grant fails the connection.
- `SELECT(name, valid_until) ON system.users` lets the sweep find expired temp users. The sweep
  itself keeps to names with the prefix; there is deliberately no row policy on `system.users`,
  because a row policy on a system table hides its rows from every user without one.
- There is deliberately **no `ALTER USER`**: `ALTER USER chauth_tmp_x RENAME TO anything` passes the
  prefix check and would move a user out of the prefix, beyond the sweep and beyond the admin's
  reach. Temp users are never altered; a changed binding gives a new user.
- Limit the admin with `HOST IP` to the network chauth connects from; `tempUserHostIPs` puts the
  same limit on every temp user.

## Access rules

```yaml
apiVersion: chauth.dev/v1alpha1
kind: ChRole
metadata: {name: analytics-read}
spec:
  grants:
    - {instance: main, database: core, level: read}
    - {instance: main, role: chauth_querylog_read, level: read}
---
apiVersion: chauth.dev/v1alpha1
kind: ChRoleBinding
metadata: {name: viewers-analytics}
spec:
  roleRef: {kind: ChRole, name: analytics-read}
  subjects: [{kind: Group, name: viewers}]
```

Every configured database also has built-in roles `<instance>.<db>.read` and `<instance>.<db>.write`.
The level a binding gives is capped by the token's scope. Details, the serve config and the connect
config: [`docs/config.md`](docs/config.md).

## Security notes

- The token is checked only by chauth; ClickHouse sees a temp user with a random password. Tokens
  and query text are never logged or traced.
- Access ends by dropping the temp user, not by `VALID UNTIL`, which only stops new logins. A revoke
  stops new connections and HTTP requests at once; an open native connection runs until it closes or
  is cut at `maxConnectionAge`.
- Clients cannot change what they are: chauth refuses the interserver and SSH-key login markers,
  removes every client credential and `quota_key` on HTTP, refuses HTTP sessions, and sets
  `log_comment` and `readonly` as `CONST` settings of the temp user.
- Before a token is accepted, a client may send at most `preAuthMaxBytes` (64 KiB) within
  `handshakeTimeout` (30 s). Upstream TLS is always verified (`verify-full`, or `verify-ca`).
- The admin user can grant or revoke its roles on any existing ClickHouse user; keep its credentials
  with chauth alone and limit it by `HOST IP`.
- The connector listens only on loopback addresses and never runs a configured command: tokens come
  from a browser login or a file ([ADR 0004](docs/adr/0004-tokens-from-login-or-file.md)).

## Development

```
go test -race ./...
```

Tests that need ClickHouse run against a real `clickhouse/clickhouse-server` container through
testcontainers, so they need Docker. Design decisions are in [`docs/adr`](docs/adr) and the
vocabulary in [`GLOSSARY.md`](GLOSSARY.md).

chauth is derived from [pgauth](https://github.com/LucStr/pgauth), the same idea for Postgres
([ADR 0006](docs/adr/0006-copied-from-pgauth.md)).

## License

Apache-2.0; see [`LICENSE`](LICENSE) and [`NOTICE`](NOTICE).
