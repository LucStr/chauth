# Configuration

chauth has two config files: the serve config (`chauth serve --config`), read by the proxy next to
ClickHouse, and `connect.yaml`, read by the connector on a laptop or in an agent's runtime. Access
rules are a third input: a directory of `ChRole` / `ChRoleBinding` YAML. Why it works this way:
[ADR 0001](adr/0001-temp-users-both-protocols.md).

```
clickhouse-client --host chauth.example.com --port 9440 --secure \
  --user " JWT AUTHENTICATION " --password "$TOKEN" -d core            # or --jwt "$TOKEN"
curl -H "Authorization: Bearer $TOKEN" "https://chauth.example.com:8443/?database=core" --data-binary 'SELECT 1'
chauth connect   # then: clickhouse-client -d prod/core, curl localhost:8123 --data-binary 'SELECT 1'
```

## Serve config

`chauth serve --config /etc/chauth/config.yaml`. Every key with its default:
[`examples/config.yaml`](../examples/config.yaml).

| Key | Default | Meaning |
| --- | --- | --- |
| `listen.native` / `listen.http` / `listen.health` | `:9440` / `:8443` / `:8080` | native TLS, HTTPS, health (`""` disables health) |
| `accessHelp` | none | appended to every "no binding grants it" denial: where to ask for access |
| `tls.certFile`, `tls.keyFile` | required | certificate of both listeners |
| `oidc.issuer`, `oidc.audience` | required | token issuer and audience |
| `oidc.allowedClients` | required, non-empty | clients whose tokens are accepted; startup fails when empty |
| `oidc.usernameClaim` / `groupsClaim` / `clientIdClaim` | `email` / `groups` / `client_id` | claim names; the client id falls back to `azp` |
| `oidc.usernameCaseInsensitive` | `true` | compare `User` subjects ignoring case; privileged bindings are safer on groups than on individual names |
| `oidc.groupsPrefix` | none | prepended to every group before bindings are matched |
| `oidc.scopes.read` / `.write` | `clickhouse:read` / `clickhouse:write` | scope cap; a token with neither is refused |
| `rbac.dir` | required | `ChRole` / `ChRoleBinding` YAML, reread every `rbac.reloadInterval` (`10s`, must be positive) |
| `limits.maxConnectionAge` | `12h` | a native connection is cut after this |
| `limits.leaseDuration` | half of `maxConnectionAge` | how long one temp user is handed out |
| `limits.tempUserIdleTTL` | `5m` | an unused temp user is dropped after this |
| `limits.sweepInterval` | `1m` | sweep of expired temp users of any process |
| `limits.selfTestInterval` | `10m` | how often each instance's temp-user path is proven again ([readiness](#readiness)); must be positive |
| `limits.maxConnectionsPerUser` / `maxConnectionsPerTempUser` | `50` / `20` | concurrency caps |
| `limits.handshakeTimeout` / `preAuthMaxBytes` | `10s` / `65536` | before the token is accepted: TLS plus Hello, or TLS plus request headers |
| `limits.maxPreAuthConnections` | `512` | native connections still before a verified token, TLS handshake included; one more is closed at once |
| `limits.maxPreAuthConnectionsPerIP` | `0` (off) | the same per client address; leave it off behind a load balancer that rewrites source addresses, where many clients share one |
| `limits.maxHTTPConnections` | `2048` | open connections on the HTTPS port; more wait in the kernel's accept queue |
| `limits.shutdownGrace` | `10s` | on SIGTERM, how long running HTTP requests may finish ([shutdown](#shutdown)) |
| `instances[].name` | required | used in grants and built-in role names; no `/` or `.` |
| `instances[].native` / `.http` | required | upstream `host:port` (native TLS) and `https://` URL |
| `instances[].tlsMode` | `verify-full` | or `verify-ca`; `caFile` (system roots), `tlsServerName` (the URL's host) |
| `instances[].databases` | required | databases served; each maps through `roleTemplate` and needs both its read and its write role upstream, held by the admin `WITH ADMIN OPTION`, unless it is in `readOnlyDatabases` (read role only): the [readiness](#readiness) self-test grants them all |
| `instances[].readOnlyDatabases` | none | databases where every grant gives only the read role; each must be in `databases` |
| `instances[].roles` | none | upstream roles a grant may name, granted verbatim (see the warning under [Rules](#rules)) |
| `instances[].credentialsFile` | required | `{"username", "password"}` of the admin login |
| `instances[].tempUserPrefix` | `chauth_tmp_` | the admin's `CREATE USER, DROP USER ON <prefix>*` |
| `instances[].tempUserHostIPs` | none | CIDRs for every temp user's `HOST IP` |
| `instances[].roleTemplate` | `chauth_{database}_{level}` | upstream role of a database grant |

Every upstream role chauth grants, named in `roles` or made by `roleTemplate` from each database and
level, must match `^[A-Za-z_][A-Za-z0-9_]*$`; the config is refused, also by `chauth lint --config`,
naming the database whose role does not. ClickHouse compares role names case-sensitively, so
`databases: [Core]` needs the upstream role `chauth_Core_read`.

## Rules

Kinds `ChRole` and `ChRoleBinding`, apiVersion `chauth.dev/v1alpha1`, shaped like Kubernetes RBAC.
Built-in roles are only `<instance>.<db>.read` and `<instance>.<db>.write` for each configured
database; there is no admin or reader role. A grant is either a database grant or a named-role grant:

```yaml
spec:
  grants:
    - {instance: main, database: core, level: write}              # chauth_core_write
    - {instance: main, database: "*", level: read}                # every database of main
    - {instance: main, role: chauth_querylog_read, level: read}   # must be in instances[].roles
```

A named role is granted verbatim. A role holding `REMOTE`, `CLUSTER`, `URL` or `FILE` reaches beyond
the per-database model (other servers, files, URLs), so bind such roles to administrators only.

The temp user gets, for every database the holder reaches on the instance, the template role at
`min(binding level, scope cap)`, plus each named role whose level the scope cap reaches. The target
database only sets the session default, because a ClickHouse query can name any database.

**Read-only databases.** On a database in `instances[].readOnlyDatabases` (for example `system`),
every grant gives only the read role, including a write grant on `database: "*"`, so
`chauth_system_write` never has to exist. An explicit `{database: system, level: write}` is a
mistake and `chauth lint --config` rejects it; serve caps it to read.

`chauth lint [--config config.yaml] <dir>` checks the rules offline. Without `--config` it checks
each object and the references between them; with it, also instances, databases, the roles
allowlist and read-only databases. Every `*.yaml` directly in `<dir>` is read except
`kustomization.yaml`. A file with no object is an error (delete it instead of emptying it), and so is a
directory that is missing, unreadable or holds no rule file; to deny everyone, keep `ChRole`s
without bindings. serve is not ready until a valid set loads, and keeps the last valid set when a
change is rejected ([ADR 0002](adr/0002-authorization-as-code.md)).
See [`examples/rbac`](../examples/rbac).

## Addresses

serve takes `<db>`, `<instance>/<db>` or nothing (ClickHouse's `default`; needs `<instance>/` when
several instances are configured). `default` itself is the same as nothing, since many clients send it. The connector takes `<env>/<db>`, strips `<env>/` and forwards
the rest. On a listener bound to an environment, a name without a known `<env>/` prefix, the empty
one included, is in that environment ([ADR 0005](adr/0005-no-default-environment.md)).

## Upstream setup

[`examples/clickhouse-setup.sql`](../examples/clickhouse-setup.sql) creates the roles and the admin
login for two databases, the read-only database `system` and one named role; the tests run it as is
and the README shows it verbatim, so its admin grants are the complete set chauth needs. The admin
needs no `ALTER USER`, no `KILL QUERY`, no row policy and no direct grants.

## Readiness

`GET /readyz` answers 200 once the issuer's keys and a valid rules set are loaded and every instance
is ready. An instance is ready after the admin login works, a first sweep ran and a self-test passed:
serve creates `<tempUserPrefix>_selftest_<pod><random>` (no person's temp user starts with `<tempUserPrefix>_`) with the same statement real temp users get
(generated password, a `VALID UNTIL` minutes ahead, `tempUserHostIPs`, `log_comment` and
`readonly = 2` as `CONST`), grants it in one statement every role the instance can hand out (each
database's roles at both levels after `readOnlyDatabases`, plus `roles`), then in a second statement
the four table privileges on every database outside `readOnlyDatabases`, logs in as it the way a new
temp user is first logged in, and drops it. Until it passes, retried with backoff up to 5 s, the
instance refuses connections with 210 / 503. It repeats every `limits.selfTestInterval`. Once ready,
an instance turns not ready only after 3 failed checks in a row, retried 1 s apart, and then retries
with backoff up to 5 s; one passing check makes it ready again at once, and open connections and
running queries are never touched. Each change logs once: `instance ready` with the roles, or
`instance not ready` with `failures` and the last failure's `step` (`admin login`, `sweep`, `self-test: create temp user`,
`self-test: grant roles to temp user`, `self-test: grant tables to temp user`, `read role grants`, `self-test: first login of temp user`, `self-test: drop temp
user`) and ClickHouse's `error`. A login failure (516) means the password, the `HOST IP` or a replica
the user has not reached within 10 s. The metrics `chauth.selftest.ok` (1 or 0) and
`chauth.selftest.time` (Unix seconds) per `chauth.instance` hold the last result, and
`chauth.selftest.runs` counts runs by `result` (`pass`, `fail`); self-tests never count in
`chauth.users.*`. The self-test user
is never handed out; one left by a crash expires and the sweep drops it.

## Discovery and access

serve's HTTPS port answers four requests of its own; every other path is proxied to ClickHouse.
`GET /ping` answers `Ok.` without a token.

`GET /.well-known/chauth`, no authentication: what a connector needs to log in and to list targets.
`native` and `http` are the request's host with the listen ports.

```json
{"native": "chauth.example.com:9440", "http": "https://chauth.example.com:8443",
 "issuer": "https://auth.example.com/", "audience": "https://clickhouse.example.com",
 "scopes": {"read": "clickhouse:read", "write": "clickhouse:write"},
 "instances": [{"name": "main", "databases": ["core", "otel", "system"], "roles": ["chauth_querylog_read"]}],
 "access_help": "Ask for access at https://access.example.com."}
```

`GET /v1/access` with `Authorization: Bearer <token>`: what this token reaches after the scope cap
and the read-only cap, one entry per instance with anything reachable (`[]` when nothing is; 401 with
`{"error": ...}` for a refused token).

```json
[{"instance": "main", "level": "write",
  "databases": [{"database": "core", "level": "write"}, {"database": "system", "level": "read"}],
  "roles": ["chauth_querylog_read"]}]
```

A database reached through [authorization details](#authorization-details) tables lists them as
`"tables": [{"table": "items", "verb": "insert"}]`. `level` is the temp user's level on that instance: `write` when any database or named role is
reached at write, else `read` (the temp user then has `readonly = 2`). `chauth ls` prints these
entries as a database table followed by the named roles. The types are `internal/chapi`.

## Authorization details

A token may carry the `authorization_details` claim (RFC 9396) to narrow what its bindings give. A
token without it gets exactly what the bindings and the scope cap give. Each row:

```json
[{"type": "clickhouse", "locations": ["https://clickhouse.example.com"], "identifier": "*", "actions": ["read"]},
 {"type": "clickhouse", "locations": ["https://clickhouse.example.com"], "identifier": "core", "actions": ["write"]},
 {"type": "clickhouse", "locations": ["https://clickhouse.example.com"], "identifier": "core",
  "tables": [{"name": "items", "verbs": ["insert", "select"]}]}]
```

| Field | Rule |
| --- | --- |
| `type` | rows of another type are skipped |
| `locations` | exactly one, equal to `oidc.audience` |
| `identifier` | `*` or a database name (on every instance that serves it); the database's own rows win over `*` |
| `actions` | consent row: `read` or `write` (write includes read), the whole database at most at that level |
| `tables` | run row: `[{name, verbs}]`, the bare table name and any of `select`, `insert`, `update`, `delete`; a database with run rows reaches only those tables |

A present claim that is `null` or not an array, a row with an unknown field, both or neither of
`actions` and `tables`, `tables` on `*`, or a location other than the audience refuses the token
(497, or 401 on `/v1/access`); only an absent claim means no claim.

chauth caps by bindings ∩ scope cap ∩ the rows in the token, and every row only narrows. A
database's consent level is its own `actions` rows, else the `*` rows. Run rows keep each verb the
level allows (`select` needs read, the rest write) when the token also carries a consent row for
that database, else the bindings after the scope cap; a token whose verbs all exceed it is refused
on that database. A narrowed run token carries only run rows: that the run stays within consent is
the issuer's check, not chauth's. A database without a row is not reached. Named roles
(`instances[].roles`) follow the lowest consent row when a `*` row exists, and are dropped without
one or when any row names tables. On a read-only database run rows keep only `select`.

A run row's verb is also kept only when the role the binding gives on that database
(`roleTemplate` at the binding's level after the caps) holds it itself, read from `system.grants`
after every passing self-test: a grant on the database or the table, or a parent privilege
(`ALTER` for `ALTER UPDATE`); a column-level grant, a partial revoke touching the table, or a role
granted to that role count as not holding it. So a direct table grant never reaches past what the
binding's role reaches.

Tables are granted to the temp user directly (`SELECT`, `INSERT`, `ALTER UPDATE`, `ALTER DELETE` on
`<db>.<table>`), never DDL, and go away with the user; the template roles of that database are not
granted. The admin needs those privileges on `<db>.*` `WITH GRANT OPTION`, `SELECT` only on a
read-only database, and `SELECT` on the listed columns of `system.grants` ([upstream
setup](#upstream-setup)). Every `connect` line logs them as `tables` (`<db>.<table>:<verb>`).

`GET /v1/tables?db=<db>` (or `<instance>/<db>`) with `Authorization: Bearer <token>`: the tables of a
database the token reaches, with the rows of their active parts; a token limited to tables gets only
those tables. 403 when the token reaches nothing in the database, 404 for an empty, unknown or
unserved `db`.

```json
[{"schema": "core", "table": "items", "estimatedRows": 48000}]
```

## Errors

Both serve and the connector answer a refusal the way ClickHouse does: on native one Exception packet
named `DB::Exception`, on HTTP a status with `X-ClickHouse-Exception-Code`. Code 516 is never sent,
because `clickhouse-client` answers it with a password prompt.

| Code | Meaning | HTTP status |
| --- | --- | --- |
| 497 `ACCESS_DENIED` | token missing, refused or expired; no binding; no scope; a web page at the connector | 401, or 403 for a valid token or a web page |
| 81 `UNKNOWN_DATABASE` | unknown environment, instance or database | 400 |
| 210 `NETWORK_ERROR` | upstream or serve unreachable, temp user not created | 502 / 503 |
| 202 `TOO_MANY_SIMULTANEOUS_QUERIES` | `maxConnectionsPerUser` reached | 429 |
| 101 `UNEXPECTED_PACKET_FROM_CLIENT` | the connector got something other than a Hello | (native only) |

## Shutdown

On SIGTERM or SIGINT serve stops accepting on both ports, lets running HTTP requests finish for
`limits.shutdownGrace` (10 s), then cuts every remaining native and HTTP connection, cancels the
upstream queries of cut HTTP requests (at most 5 s), and drops the temp users this process created
(at most 10 s) before it exits. It therefore stops within `shutdownGrace` + 5 s + 10 s, about 25 s
by default. A deployment's termination grace period (Kubernetes: 30 s by default) must exceed that
bound, or the process is killed before it drops its temp users; the sweep of another instance drops
them only once their `VALID UNTIL` has passed.

## Connect config

`chauth connect` reads `--config`, else `$CHAUTH_CONFIG`, else `<user config dir>/chauth/connect.yaml`;
example: [`examples/connect.yaml`](../examples/connect.yaml).

- `environments.<env>.server`: serve's native `host:port`; `httpServer`: serve's `https://` URL,
  which also answers `GET /.well-known/chauth` and `GET /v1/access` (used by `chauth ls`, see
  [above](#discovery-and-access));
  `serverCA`: a PEM file to trust instead of the system roots (also top-level for every environment).
- `environments.<env>.token`: `login: browser` with `issuer`, `clientId`, `resource`, `scope`
  (refresh token in the OS keychain under `chauth`), or `file`, `field`, `statusFile` (re-read on
  every connection; [ADR 0004](adr/0004-tokens-from-login-or-file.md)).
- `listen` (default `127.0.0.1:9000`) and `listenHTTP` (default `127.0.0.1:8123`): local ports with
  no default environment.
- `listeners: [{listen, listenHTTP, env}]`: local ports bound to an environment; either address may
  be left out. A bound listener on the top-level address takes it over.
- The browser login runs on `chauth login <env>` and on the first native connection without a stored
  login; the HTTP port never starts one and answers 401 naming `chauth login <env>`. The HTTP port
  refuses requests from web pages ([ADR 0004](adr/0004-tokens-from-login-or-file.md)).
- `callbackPort` (default `8250`): loopback port of the browser login redirect; `0` picks a free one.

Every local address must be a loopback address: the connector serves this machine only.
