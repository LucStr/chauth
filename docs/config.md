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
| `oidc.usernameCaseInsensitive` | `true` | compare `User` subjects ignoring case |
| `oidc.groupsPrefix` | none | prepended to every group before bindings are matched |
| `oidc.scopes.read` / `.write` | `clickhouse:read` / `clickhouse:write` | scope cap; a token with neither is refused |
| `rbac.dir` | required | `ChRole` / `ChRoleBinding` YAML, reread every `rbac.reloadInterval` (`10s`) |
| `limits.maxConnectionAge` | `12h` | a native connection is cut after this |
| `limits.leaseDuration` | half of `maxConnectionAge` | how long one temp user is handed out |
| `limits.tempUserIdleTTL` | `5m` | an unused temp user is dropped after this |
| `limits.sweepInterval` | `1m` | sweep of expired temp users of any process |
| `limits.maxConnectionsPerUser` / `maxConnectionsPerTempUser` | `50` / `20` | concurrency caps |
| `limits.handshakeTimeout` / `preAuthMaxBytes` | `30s` / `65536` | before the token is accepted |
| `instances[].name` | required | used in grants and built-in role names; no `/` or `.` |
| `instances[].native` / `.http` | required | upstream `host:port` (native TLS) and `https://` URL |
| `instances[].tlsMode` | `verify-full` | or `verify-ca`; `caFile` (system roots), `tlsServerName` (the URL's host) |
| `instances[].databases` | required | databases served; each maps through `roleTemplate` |
| `instances[].readOnlyDatabases` | none | databases where every grant gives only the read role; each must be in `databases` |
| `instances[].roles` | none | upstream roles a grant may name |
| `instances[].credentialsFile` | required | `{"username", "password"}` of the admin login |
| `instances[].tempUserPrefix` | `chauth_tmp_` | the admin's `CREATE USER, DROP USER ON <prefix>*` |
| `instances[].tempUserHostIPs` | none | CIDRs for every temp user's `HOST IP` |
| `instances[].roleTemplate` | `chauth_{database}_{level}` | upstream role of a database grant |

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
`kustomization.yaml`. A file with no object is an error (delete it instead of emptying it), and
serve keeps the last valid set when a change is rejected ([ADR 0002](adr/0002-authorization-as-code.md)).
See [`examples/rbac`](../examples/rbac).

## Addresses

serve takes `<db>`, `<instance>/<db>` or nothing (ClickHouse's `default`; needs `<instance>/` when
several instances are configured). The connector takes `<env>/<db>`, strips `<env>/` and forwards
the rest. On a listener bound to an environment, a name without a known `<env>/` prefix, the empty
one included, is in that environment ([ADR 0005](adr/0005-no-default-environment.md)).

## Upstream setup

[`examples/clickhouse-setup.sql`](../examples/clickhouse-setup.sql) creates the roles and the admin
login for two databases, the read-only database `system` and one named role; the tests run it as is
and the README shows it verbatim, so its admin grants are the complete set chauth needs. The admin
needs no `ALTER USER`, no `KILL QUERY`, no row policy and no direct grants.

## Discovery and access

serve's HTTPS port answers three requests of its own; every other path is proxied to ClickHouse.
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

`level` is the temp user's level on that instance: `write` when any database or named role is
reached at write, else `read` (the temp user then has `readonly = 2`). `chauth ls` prints these
entries as a database table followed by the named roles. The types are `internal/chapi`.

## Errors

Both serve and the connector answer a refusal the way ClickHouse does: on native one Exception packet
named `DB::Exception`, on HTTP a status with `X-ClickHouse-Exception-Code`. Code 516 is never sent,
because `clickhouse-client` answers it with a password prompt.

| Code | Meaning | HTTP status |
| --- | --- | --- |
| 497 `ACCESS_DENIED` | token missing, refused or expired; no binding; no scope | 401, or 403 for a valid token |
| 81 `UNKNOWN_DATABASE` | unknown environment, instance or database | 400 |
| 210 `NETWORK_ERROR` | upstream or serve unreachable, temp user not created | 502 / 503 |
| 202 `TOO_MANY_SIMULTANEOUS_QUERIES` | `maxConnectionsPerUser` reached | 429 |
| 101 `UNEXPECTED_PACKET_FROM_CLIENT` | the connector got something other than a Hello | (native only) |

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
- `callbackPort` (default `8250`): loopback port of the browser login redirect; `0` picks a free one.

Every local address must be a loopback address: the connector serves this machine only.
