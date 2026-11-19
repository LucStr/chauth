# Changelog

## Unreleased

- Tokens may carry `authorization_details` (RFC 9396, type `clickhouse`): consent rows narrow each
  database to read or write, run rows narrow a database to declared tables and verbs, granted to the
  temp user directly as `SELECT`, `INSERT`, `ALTER UPDATE`, `ALTER DELETE` and never DDL. chauth caps
  by bindings ∩ scope cap ∩ the rows in the token; a consent row caps the verbs of that database's run
  rows, and a run verb is kept only when the binding's role holds it (`system.grants`, a
  partial revoke anywhere in the database counting for every table), and a database with a row
  policy gets no run rows. Named roles
  follow the lowest consent row and are dropped for a token with table rows. Unknown fields or a `null` claim refuse the token; a token without the claim is unchanged.
  `/v1/access` shows the tables, and `connect` lines log them as `tables`.
- `GET /v1/tables?db=<db>`: the tables of a database the token reaches (only its declared tables for
  a run token), with row estimates from active parts; 404 for an unknown database.

Upgrading: before rolling out, grant the admin `SELECT, INSERT, ALTER UPDATE, ALTER DELETE ON <db>.*
WITH GRANT OPTION` for every database in `databases` (`SELECT` only on a read-only one, such as
`system`), `SELECT(role_name, access_type, database, table, column, is_partial_revoke) ON
system.grants`, `SELECT(database) ON system.row_policies` and `SELECT(database, table, rows,
active) ON system.parts`; see
`examples/clickhouse-setup.sql`. Readiness now depends on them for every token, not only for tokens
with `authorization_details`: the self-test grants the table privileges and reads the role grants,
so without them the instance never becomes ready and refuses every connection, and the log names the
step `self-test: grant tables to temp user` or `read role grants`. Roll out with old pods kept until
new ones are ready.

## v0.1.1 (2026-11-17)

- Fix: temp-user passwords had only lower-case letters and digits, so a server with password
  complexity rules, such as every ClickHouse Cloud service, refused every temp user and every
  connection failed. They are now 32 random characters with at least two upper-case letters,
  lower-case letters, digits and characters of `!#%*+-=_` each. The tests run ClickHouse with
  ClickHouse Cloud's default rules.
- serve is ready only after a self-test per instance: create a temp user the way real ones are made,
  grant it every role the instance can hand out, log in as it and drop it. It repeats every
  `limits.selfTestInterval` (10m); once ready, an instance turns not ready only after 3 failed checks
  in a row and is ready again after one pass, logging each change once with the failed step and
  ClickHouse's error. Metrics `chauth.selftest.ok`, `chauth.selftest.time` and `chauth.selftest.runs`.

Upgrading from v0.1.0: the self-test grants every role an instance can hand out, so every database
in `databases` needs both its read and its write role upstream, held by the admin `WITH ADMIN
OPTION`, or must be listed in `readOnlyDatabases`. A deployment that created only the read role for
some database must add it to `readOnlyDatabases` or create its write role before upgrading;
otherwise the instance never becomes ready and the log names the missing role.
- `examples/clickhouse-setup.sql`: the example admin password meets the same rules.

## v0.1.0 (2026-11-17)

First release.

- `chauth serve`: ClickHouse's native protocol over TLS and its HTTPS interface with an OIDC access
  token as the credential. Access comes from `ChRole` / `ChRoleBinding` rules (`chauth.dev/v1alpha1`)
  capped by the token's scope; chauth logs in upstream as a temp user holding exactly those upstream
  roles, reuses it for `leaseDuration`, drops it after its last use and sweeps expired ones.
  Per-instance `readOnlyDatabases` give only the read role for every grant. Native connections are
  cut at `maxConnectionAge`; per-user and per-temp-user concurrency limits; pre-auth size and time
  limits; certificate reload; `/healthz`, `/readyz`; `/.well-known/chauth` and `/v1/access`;
  OTel traces, metrics and logs; a `connect` and a `disconnect` audit line per native connection.
- `chauth connect`: local native and HTTP ports that route `<env>/<db>` to an environment and add
  its token from a browser login (PKCE, refresh token in the OS keychain, redirect
  `http://127.0.0.1:8250/callback`) or a token file; listeners bound to one environment.
  The local HTTP port refuses web pages (`Origin`, `Sec-Fetch-Site`, non-loopback `Host`) and never
  opens a browser login.
- serve bounds unauthenticated connections (`maxPreAuthConnections`, `maxPreAuthConnectionsPerIP`,
  `maxHTTPConnections`), cancels the upstream query of an HTTP request whose client left, and shuts
  down within `shutdownGrace` + 10 s, dropping its temp users.
- `chauth ls`, `login`, `logout`, `service install|uninstall`, `lint`, `version`.
- `examples/clickhouse-setup.sql`: the upstream roles and admin login, run by the tests.
- Image `ghcr.io/lucstr/chauth` and binaries for macOS and Linux (amd64, arm64).
