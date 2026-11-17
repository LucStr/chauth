# Changelog

## Unreleased

First release, v0.1.0:

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
- `chauth ls`, `login`, `logout`, `service install|uninstall`, `lint`, `version`.
- `examples/clickhouse-setup.sql`: the upstream roles and admin login, run by the tests.
- Image `ghcr.io/lucstr/chauth` and binaries for macOS and Linux (amd64, arm64).
